import 'dotenv/config';
import crypto from 'crypto';
import express from 'express';
import multer from 'multer';
import path from 'path';
import { createServer as createViteServer } from 'vite';
import {
  KAVERI_BASELINE_FINANCIALS,
  KAVERI_DOCUMENTS,
  KAVERI_EVIDENCE_EDGES,
  KAVERI_EVIDENCE_NODES,
  KAVERI_FINDINGS,
  KAVERI_TRANSACTION_EDGES,
} from './src/data/kaveriDemoData';
import {
  normalizeDocumentCategory,
  suggestMsmeClassification,
} from './src/data/msmeDocumentTaxonomy';
import { EvidenceDocumentItem } from './src/types/evidenceos';
import { buildEvidenceGraphFromDocuments } from './src/utils/evidenceGraphBuilder';
import {
  computeCreditAssessment,
  DEFAULT_CREDIT_WEIGHTS,
  detectDirectedCycles,
  runFinancialStressSimulation,
} from './src/utils/financialEngines';
import {
  extractDocumentWithGemini,
  OCR_LITE_MODEL,
  REASONING_MODEL,
  recheckDocumentWithGemini,
  runInvestigatorAgent,
} from './server/services/geminiService';
import {
  addWorkspaceDocument,
  findDuplicateByHash,
  getWorkspaceDocuments,
  getWorkspaceGraph,
  removeWorkspaceDocument,
  replaceWorkspaceDocument,
  updateWorkspaceDocumentClassification,
} from './server/services/documentStore';
import {
  AGENT_REGISTRY_METADATA,
  orchestrateMultiAgentInvestigation,
} from './server/services/multiAgent/orchestrator';
import { getMultiAgentRunById, listMultiAgentRuns } from './server/services/multiAgent/runStore';
import {
  MAX_UPLOAD_BYTES,
  resolveWorkspaceScope,
  RETENTION_POLICY_DAYS,
  validateUploadedFileIntegrity,
} from './server/services/privacy/privacyPolicy';
import {
  assertWorkspaceAccess,
  buildDocumentPrivacyMetadata,
  detectProhibitedWhatsAppPayload,
  extractActorContext,
  scanAndMinimizePersonalData,
} from './server/services/privacy/privacyLayer';
import {
  applyLegacyRecordDisposition,
  getRetentionPolicy,
  listDeletedDocumentIds,
  listLegacyQuarantinedRecords,
  markDocumentDeleted,
  updateRetentionPolicy,
} from './server/services/privacy/legacyMigrationStore';

const PORT = 3000;
const PYTHON_BACKEND_URL = (process.env.PYTHON_BACKEND_URL || '').trim();
const BACKEND_SERVICE_TOKEN = (process.env.BACKEND_SERVICE_TOKEN || '').trim();
const DEMO_MODE = process.env.DEMO_MODE !== 'false';

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: MAX_UPLOAD_BYTES },
});

/**
 * Optional proxy helper: forwards to external Python FastAPI backend if PYTHON_BACKEND_URL is configured.
 * Returns null if unconfigured or unreachable so the Node BFF handles the request directly.
 */
async function tryProxyPythonBackend(
  endpoint: string,
  method: string,
  body?: unknown
): Promise<{ status: number; data: unknown } | null> {
  if (!PYTHON_BACKEND_URL) return null;
  try {
    const res = await fetch(`${PYTHON_BACKEND_URL.replace(/\/$/, '')}${endpoint}`, {
      method,
      headers: {
        'Content-Type': 'application/json',
        ...(BACKEND_SERVICE_TOKEN ? { Authorization: `Bearer ${BACKEND_SERVICE_TOKEN}` } : {}),
      },
      body: body !== undefined ? JSON.stringify(body) : undefined,
      signal: AbortSignal.timeout(4000),
    });
    const data = await res.json();
    return { status: res.status, data };
  } catch {
    return null;
  }
}

async function startServer() {
  const app = express();
  app.use(express.json({ limit: '25mb' }));

  // Health Endpoint (both /health and /api/health)
  const healthHandler = async (_req: express.Request, res: express.Response) => {
    const pyCheck = await tryProxyPythonBackend('/health', 'GET');
    res.json({
      status: 'ok',
      service: 'evidenceos-node-bff',
      demoMode: !pyCheck && DEMO_MODE,
      pythonBackendConfigured: Boolean(PYTHON_BACKEND_URL),
      pythonBackendReachable: Boolean(pyCheck && pyCheck.status === 200),
      privacyLayerEnabled: true,
      whatsappDecommissioned: true,
      paddleOcrEnabled: process.env.ENABLE_PADDLE_OCR === 'true',
      geminiModel: OCR_LITE_MODEL,
      geminiReasoningModel: REASONING_MODEL,
      retentionPolicyDays: getRetentionPolicy().defaultRetentionDays || RETENTION_POLICY_DAYS,
      allowedUploadFormats: ['PDF', 'JPG', 'JPEG', 'PNG'],
      timestamp: new Date().toISOString(),
    });
  };
  app.get('/health', healthHandler);
  app.get('/api/health', healthHandler);

  // Privacy, Retention Policy & Non-Destructive Legacy WhatsApp Quarantine Endpoints
  app.get('/api/v1/privacy/policy', (req, res) => {
    const scope = resolveWorkspaceScope(req);
    const actor = extractActorContext(req.headers as Record<string, unknown>, scope.businessId);
    const access = assertWorkspaceAccess(actor, scope.businessId, 'read');
    if (!access.allowed) return res.status(access.status).json({ error: access.error });
    return res.json({
      businessId: scope.businessId,
      retentionPolicy: getRetentionPolicy(),
      deletedDocumentIds: listDeletedDocumentIds(),
    });
  });

  app.put('/api/v1/privacy/retention', (req, res) => {
    const scope = resolveWorkspaceScope(req);
    const actor = extractActorContext(req.headers as Record<string, unknown>, scope.businessId);
    const access = assertWorkspaceAccess(actor, scope.businessId, 'manage_policy');
    if (!access.allowed) return res.status(access.status).json({ error: access.error });
    const nextPolicy = updateRetentionPolicy(
      {
        defaultRetentionDays: req.body?.defaultRetentionDays,
        autoRedactPersonalIdentifiers: req.body?.autoRedactPersonalIdentifiers,
        requireSubmitterAuthorization: req.body?.requireSubmitterAuthorization,
        restrictRawDocumentToPrivilegedRoles: req.body?.restrictRawDocumentToPrivilegedRoles,
      },
      { userId: actor.userId, role: actor.role }
    );
    return res.json({ retentionPolicy: nextPolicy });
  });

  app.get('/api/v1/privacy/legacy-migration', (req, res) => {
    const scope = resolveWorkspaceScope(req);
    const actor = extractActorContext(req.headers as Record<string, unknown>, scope.businessId);
    const access = assertWorkspaceAccess(actor, scope.businessId, 'read');
    if (!access.allowed) return res.status(access.status).json({ error: access.error });
    return res.json({
      businessId: scope.businessId,
      records: listLegacyQuarantinedRecords(scope.businessId),
    });
  });

  app.post('/api/v1/privacy/legacy-migration/:recordId/disposition', (req, res) => {
    const scope = resolveWorkspaceScope(req);
    const actor = extractActorContext(req.headers as Record<string, unknown>, scope.businessId);
    const access = assertWorkspaceAccess(actor, scope.businessId, 'manage_policy');
    if (!access.allowed) return res.status(access.status).json({ error: access.error });
    const disposition =
      req.body?.disposition === 'purge_authorized'
        ? 'purge_authorized'
        : 'archive_compliance_receipt';
    const updated = applyLegacyRecordDisposition({
      recordId: String(req.params.recordId || ''),
      disposition,
      note: String(req.body?.note || ''),
      actor: { userId: actor.userId, role: actor.role },
    });
    if (!updated) {
      return res.status(404).json({ error: 'Legacy quarantined record not found.' });
    }
    return res.json({ record: updated });
  });

  // Instant MSME Document Classification Suggestion Endpoint
  app.post('/api/v1/documents/classify', (req, res) => {
    const fileName = String(req.body?.fileName || '').trim();
    const textHint = typeof req.body?.textHint === 'string' ? req.body.textHint : undefined;
    if (!fileName) {
      return res.status(400).json({ error: 'fileName is required for classification suggestion.' });
    }
    const suggestion = suggestMsmeClassification(fileName, textHint);
    return res.json({
      suggestedCategory: suggestion.category,
      suggestedSubcategory: suggestion.subcategory,
      confidence: suggestion.confidencePct,
    });
  });

  // Workspace-isolated Documents API
  app.get('/api/v1/documents', async (req, res) => {
    const proxied = await tryProxyPythonBackend('/api/v1/documents', 'GET');
    if (proxied) return res.status(proxied.status).json(proxied.data);
    const scope = resolveWorkspaceScope(req);
    const documents = getWorkspaceDocuments(scope.scopeKey, scope.businessId);
    return res.json({
      demoMode: scope.businessId === 'kaveri_textiles',
      businessId: scope.businessId,
      documents,
    });
  });

  app.get('/api/v1/documents/:documentId', async (req, res) => {
    const proxied = await tryProxyPythonBackend(`/api/v1/documents/${req.params.documentId}`, 'GET');
    if (proxied) return res.status(proxied.status).json(proxied.data);
    const scope = resolveWorkspaceScope(req);
    const docs = getWorkspaceDocuments(scope.scopeKey, scope.businessId);
    const found = docs.find((d) => d.id === req.params.documentId);
    if (!found) return res.status(404).json({ error: 'Document not found in this workspace.' });
    return res.json({ businessId: scope.businessId, document: found });
  });

  /**
   * Shared upload processor: validates magic bytes / corruption, detects SHA-256 duplicates,
   * runs category-aware Gemini extraction, stores in workspace-isolated store, and rebuilds graph.
   */
  const processUploadedBuffer = async (params: {
    req: express.Request;
    fileBuffer: Buffer;
    originalName: string;
    mimeType: string;
    category?: string;
    subcategory?: string;
    replaceDocumentId?: string;
    allowDuplicate?: boolean;
  }) => {
    const scope = resolveWorkspaceScope(params.req);
    const actor = extractActorContext(params.req.headers as Record<string, unknown>, scope.businessId);
    const access = assertWorkspaceAccess(actor, scope.businessId, 'upload');
    if (!access.allowed) {
      const err: any = new Error(access.error);
      err.statusCode = access.status;
      throw err;
    }

    const whatsappCheck = detectProhibitedWhatsAppPayload({
      fileName: params.originalName,
      category: params.category,
      subcategory: params.subcategory,
    });
    if (whatsappCheck.prohibited) {
      const err: any = new Error(whatsappCheck.reason || 'WhatsApp and personal chat uploads are not permitted.');
      err.statusCode = 403;
      throw err;
    }

    // 1. Validate format and detect corrupted/empty/truncated files before OCR
    const integrity = validateUploadedFileIntegrity(
      params.fileBuffer,
      params.originalName,
      params.mimeType
    );
    if (!integrity.valid) {
      const err: any = new Error(integrity.reason || 'File failed integrity validation.');
      err.statusCode = 422;
      err.isCorruptedOrUnreadable = Boolean(integrity.isCorruptedOrUnreadable);
      throw err;
    }

    const detectedMime = integrity.detectedMimeType || params.mimeType || 'application/pdf';
    const sha256Short = crypto
      .createHash('sha256')
      .update(params.fileBuffer)
      .digest('hex')
      .slice(0, 12);

    // 2. Duplicate detection within the isolated workspace
    const existingDuplicate = findDuplicateByHash(
      scope.scopeKey,
      scope.businessId,
      sha256Short,
      params.replaceDocumentId
    );

    const filenameHint = suggestMsmeClassification(params.originalName);
    const userSelectedCategory = params.category
      ? normalizeDocumentCategory(params.category)
      : filenameHint.category;
    const documentId =
      params.replaceDocumentId || `DOC-${Date.now().toString(36).toUpperCase()}`;

    // 3. Multimodal Gemini OCR & MSME Category Extraction
    const extraction = await extractDocumentWithGemini({
      documentId,
      fileName: params.originalName,
      category: userSelectedCategory,
      subcategory: params.subcategory || filenameHint.subcategory,
      mimeType: detectedMime,
      fileBuffer: params.fileBuffer,
    });

    const finalCategory = params.category
      ? normalizeDocumentCategory(params.category)
      : extraction.suggestedCategory;
    const finalSubcategory =
      params.subcategory?.trim() || extraction.suggestedSubcategory || filenameHint.subcategory;

    const policy = getRetentionPolicy();
    const piiScan = scanAndMinimizePersonalData(
      `${extraction.summary}\n${extraction.extractedText}`,
      { applyRedaction: policy.autoRedactPersonalIdentifiers }
    );
    const privacyMetadata = {
      ...buildDocumentPrivacyMetadata({
        authorizedBy: actor.userId,
        processingPurpose: String(
          params.req.body?.processingPurpose ||
            'MSME credit underwriting & financial evidence verification'
        ).slice(0, 240),
        containsThirdPartyPiiDeclared:
          params.req.body?.containsThirdPartyPii === true ||
          params.req.body?.containsThirdPartyPii === 'true',
        scanResult: piiScan,
        retentionPolicyDays:
          Number(params.req.body?.retentionPolicyDays) || policy.defaultRetentionDays,
        applyRedaction: policy.autoRedactPersonalIdentifiers,
      }),
      authorizedChannel: 'direct_lender_portal' as const,
      piiRedacted: true,
    };

    const newDoc: EvidenceDocumentItem = {
      id: documentId,
      businessId: scope.businessId,
      fileName: params.originalName,
      category: finalCategory,
      subcategory: finalSubcategory,
      suggestedCategory: extraction.suggestedCategory,
      suggestedSubcategory: extraction.suggestedSubcategory,
      classificationConfidence: extraction.classificationConfidence,
      classificationOverridden: Boolean(
        params.category && normalizeDocumentCategory(params.category) !== extraction.suggestedCategory
      ),
      uploadDate: new Date().toISOString(),
      fileSize: params.fileBuffer.length,
      mimeType: detectedMime,
      uploadStatus: 'uploaded',
      ocrStatus: extraction.isFinancialDocument ? 'completed' : 'failed',
      verificationStatus: extraction.verificationStatus,
      language: extraction.language,
      pageCount: extraction.pageCount,
      sha256Short,
      isDuplicate: Boolean(existingDuplicate),
      duplicateOfDocumentId: existingDuplicate?.id,
      isCorruptedOrUnreadable: false,
      reportingPeriod: extraction.reportingPeriod,
      extractedSummary: extraction.summary,
      previewText: extraction.extractedText,
      isDemo: false,
      records: extraction.records,
      structuredExtraction: extraction.structuredExtraction,
      completenessChecks: [
        {
          field: 'File Integrity & Format',
          required: true,
          present: true,
          valuePreview: detectedMime,
        },
        {
          field: 'MSME Category Match',
          required: true,
          present: extraction.isFinancialDocument,
          valuePreview: extraction.isFinancialDocument
            ? `${finalSubcategory} (${extraction.classificationConfidence}%)`
            : 'Not a supported lending document',
        },
        {
          field: 'Structured Records Extracted',
          required: true,
          present: extraction.records.length > 0,
          valuePreview: `${extraction.records.length} record(s)`,
        },
      ],
      internalConsistencyNotes: [
        ...extraction.consistencyNotes,
        ...(existingDuplicate
          ? [
              `Duplicate file detected: matches SHA-256 fingerprint of ${existingDuplicate.id} (${existingDuplicate.fileName}).`,
            ]
          : []),
      ],
      authenticityReport: extraction.authenticityReport,
      privacyMetadata,
    };

    const mutation = params.replaceDocumentId
      ? replaceWorkspaceDocument(scope.scopeKey, scope.businessId, params.replaceDocumentId, newDoc) ||
        addWorkspaceDocument(scope.scopeKey, scope.businessId, newDoc)
      : addWorkspaceDocument(scope.scopeKey, scope.businessId, newDoc);

    return {
      documentId,
      sha256Short,
      isDuplicate: Boolean(existingDuplicate),
      duplicateOfDocumentId: existingDuplicate?.id || null,
      duplicateOfFileName: existingDuplicate?.fileName || null,
      isFinancialDocument: extraction.isFinancialDocument,
      suggestedCategory: extraction.suggestedCategory,
      suggestedSubcategory: extraction.suggestedSubcategory,
      classificationConfidence: extraction.classificationConfidence,
      reportingPeriod: extraction.reportingPeriod,
      ocrStatus: newDoc.ocrStatus,
      verificationStatus: extraction.verificationStatus,
      language: extraction.language,
      pageCount: extraction.pageCount,
      modelUsed: extraction.modelUsed,
      summary: extraction.summary,
      extractedText: extraction.extractedText,
      consistencyNotes: newDoc.internalConsistencyNotes,
      records: extraction.records,
      structuredExtraction: extraction.structuredExtraction,
      authenticityReport: extraction.authenticityReport,
      privacyMetadata,
      document: mutation.document,
      graphSummary: mutation.graph.stats,
    };
  };

  // Standard Multipart Document Upload (PDF, JPG, JPEG, PNG)
  app.post('/api/v1/documents/upload', (req, res) => {
    upload.single('file')(req, res, async (multerErr: any) => {
      if (multerErr) {
        const status = multerErr.code === 'LIMIT_FILE_SIZE' ? 413 : 400;
        return res.status(status).json({
          error:
            multerErr.code === 'LIMIT_FILE_SIZE'
              ? 'File exceeds 20 MB server limit. Please compress or use a smaller file.'
              : multerErr.message || 'Invalid multipart upload request.',
        });
      }
      try {
        const file = req.file;
        if (!file) {
          return res.status(400).json({ error: 'No file attached to upload request.' });
        }
        const payload = await processUploadedBuffer({
          req,
          fileBuffer: file.buffer,
          originalName: file.originalname,
          mimeType: file.mimetype || 'application/octet-stream',
          category: typeof req.body?.category === 'string' ? req.body.category : undefined,
          subcategory: typeof req.body?.subcategory === 'string' ? req.body.subcategory : undefined,
        });
        return res.json(payload);
      } catch (err: any) {
        const status = Number(err?.statusCode) || 500;
        return res.status(status).json({
          error: err instanceof Error ? err.message : 'Document extraction failed.',
          isCorruptedOrUnreadable: Boolean(err?.isCorruptedOrUnreadable),
        });
      }
    });
  });

  // Base64 JSON upload endpoint (reliable through proxies & multi-file batch queue)
  app.post('/api/v1/documents/upload-base64', async (req, res) => {
    try {
      const { fileName, mimeType, category, subcategory, fileBase64, replaceDocumentId } =
        req.body || {};
      if (!fileBase64 || typeof fileBase64 !== 'string') {
        return res.status(400).json({ error: 'Missing base64 file content.' });
      }
      const cleanBase64 = fileBase64.includes(',') ? fileBase64.split(',')[1] : fileBase64;
      const fileBuffer = Buffer.from(cleanBase64, 'base64');
      const payload = await processUploadedBuffer({
        req,
        fileBuffer,
        originalName: String(fileName || 'uploaded-document.pdf'),
        mimeType: String(mimeType || 'application/pdf'),
        category: typeof category === 'string' ? category : undefined,
        subcategory: typeof subcategory === 'string' ? subcategory : undefined,
        replaceDocumentId: typeof replaceDocumentId === 'string' ? replaceDocumentId : undefined,
      });
      return res.json(payload);
    } catch (err: any) {
      const status = Number(err?.statusCode) || 500;
      return res.status(status).json({
        error: err instanceof Error ? err.message : 'Document extraction failed.',
        isCorruptedOrUnreadable: Boolean(err?.isCorruptedOrUnreadable),
      });
    }
  });

  // Allow user to correct document classification post-upload and rebuild evidence graph
  app.patch('/api/v1/documents/:documentId/classification', (req, res) => {
    const scope = resolveWorkspaceScope(req);
    const actor = extractActorContext(req.headers as Record<string, unknown>, scope.businessId);
    const access = assertWorkspaceAccess(actor, scope.businessId, 'upload');
    if (!access.allowed) return res.status(access.status).json({ error: access.error });

    const { category, subcategory } = req.body || {};
    if (!category || typeof category !== 'string') {
      return res.status(400).json({ error: 'Valid MSME document category is required.' });
    }
    const updated = updateWorkspaceDocumentClassification(
      scope.scopeKey,
      scope.businessId,
      String(req.params.documentId),
      category,
      typeof subcategory === 'string' ? subcategory : undefined
    );
    if (!updated) {
      return res.status(404).json({ error: 'Document not found in this workspace.' });
    }
    return res.json({
      document: updated.document,
      graphSummary: updated.graph.stats,
    });
  });

  // Authorized document replacement (base64 JSON)
  app.put('/api/v1/documents/:documentId/replace', async (req, res) => {
    try {
      const { fileName, mimeType, category, subcategory, fileBase64 } = req.body || {};
      if (!fileBase64 || typeof fileBase64 !== 'string') {
        return res.status(400).json({ error: 'Missing replacement base64 file content.' });
      }
      const cleanBase64 = fileBase64.includes(',') ? fileBase64.split(',')[1] : fileBase64;
      const fileBuffer = Buffer.from(cleanBase64, 'base64');
      const payload = await processUploadedBuffer({
        req,
        fileBuffer,
        originalName: String(fileName || 'replacement-document.pdf'),
        mimeType: String(mimeType || 'application/pdf'),
        category: typeof category === 'string' ? category : undefined,
        subcategory: typeof subcategory === 'string' ? subcategory : undefined,
        replaceDocumentId: String(req.params.documentId),
      });
      return res.json(payload);
    } catch (err: any) {
      const status = Number(err?.statusCode) || 500;
      return res.status(status).json({
        error: err instanceof Error ? err.message : 'Document replacement failed.',
        isCorruptedOrUnreadable: Boolean(err?.isCorruptedOrUnreadable),
      });
    }
  });

  // Authorized document removal + dynamic graph rebuild
  app.delete('/api/v1/documents/:documentId', (req, res) => {
    const scope = resolveWorkspaceScope(req);
    const actor = extractActorContext(req.headers as Record<string, unknown>, scope.businessId);
    const access = assertWorkspaceAccess(actor, scope.businessId, 'delete');
    if (!access.allowed) return res.status(access.status).json({ error: access.error });

    const docId = String(req.params.documentId);
    const reason = String(req.body?.reason || 'Authorized retention / deletion request');
    const result = removeWorkspaceDocument(scope.scopeKey, scope.businessId, docId);
    markDocumentDeleted(docId, scope.businessId, reason, {
      userId: actor.userId,
      role: actor.role,
    });
    return res.json({
      removed: result.removed,
      documentId: docId,
      graphSummary: result.graph.stats,
    });
  });

  // OCR Re-extraction Endpoint
  app.post('/api/v1/ocr/extract', async (req, res) => {
    try {
      const { documentId, fileName, category, textContent } = req.body || {};
      const extraction = await extractDocumentWithGemini({
        documentId: String(documentId || 'DOC-ADHOC'),
        fileName: String(fileName || 'document.pdf'),
        category: normalizeDocumentCategory(category),
        mimeType: 'text/plain',
        textContent: String(textContent || ''),
      });
      return res.json(extraction);
    } catch (err) {
      const message = err instanceof Error ? err.message : 'OCR extraction failed.';
      return res.status(500).json({ error: message });
    }
  });

  // Independent Gemini Authenticity & Field-Match Recheck Endpoint (Free-tier Gemini)
  app.post('/api/v1/ocr/recheck', async (req, res) => {
    try {
      const {
        documentId,
        fileName,
        category,
        isDemo,
        textContent,
        imageDataUrl,
        existingRecords,
      } = req.body || {};
      const hasText = Boolean(textContent && String(textContent).trim());
      const hasImage = Boolean(imageDataUrl && String(imageDataUrl).startsWith('data:image/'));
      if (!hasText && !hasImage) {
        return res.status(400).json({
          error: 'Document text or image content is required to run Gemini authenticity and match recheck.',
        });
      }
      const report = await recheckDocumentWithGemini({
        documentId: String(documentId || 'DOC-ADHOC'),
        fileName: String(fileName || 'document.pdf'),
        category: normalizeDocumentCategory(category),
        isDemo: Boolean(isDemo),
        textContent: String(textContent || ''),
        imageDataUrl: hasImage ? String(imageDataUrl) : undefined,
        existingRecords: Array.isArray(existingRecords) ? existingRecords : [],
      });
      return res.json({ report });
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Gemini document recheck failed.';
      return res.status(500).json({ error: message });
    }
  });

  // Verification Findings
  app.get('/api/v1/verification/findings', async (req, res) => {
    const proxied = await tryProxyPythonBackend('/api/v1/verification/findings', 'GET');
    if (proxied) return res.status(proxied.status).json(proxied.data);
    const scope = resolveWorkspaceScope(req);
    const graph = getWorkspaceGraph(scope.scopeKey, scope.businessId);
    const findings =
      scope.businessId === 'kaveri_textiles' ? KAVERI_FINDINGS : graph.reconciliationFindings;
    return res.json({
      demoMode: scope.businessId === 'kaveri_textiles',
      businessId: scope.businessId,
      findings,
    });
  });

  app.post('/api/v1/verification/run', async (req, res) => {
    const proxied = await tryProxyPythonBackend('/api/v1/verification/run', 'POST');
    if (proxied) return res.status(proxied.status).json(proxied.data);
    const scope = resolveWorkspaceScope(req);
    const graph = getWorkspaceGraph(scope.scopeKey, scope.businessId);
    const findings =
      scope.businessId === 'kaveri_textiles' ? KAVERI_FINDINGS : graph.reconciliationFindings;
    return res.json({
      demoMode: scope.businessId === 'kaveri_textiles',
      findingsCount: findings.length,
      findings,
    });
  });

  // Dynamic Workspace-Isolated Graph Endpoints (built from actual uploaded documents)
  app.get('/api/v1/graph/evidence', async (req, res) => {
    const proxied = await tryProxyPythonBackend('/api/v1/graph/evidence', 'GET');
    if (proxied) return res.status(proxied.status).json(proxied.data);
    const scope = resolveWorkspaceScope(req);
    const graph = getWorkspaceGraph(scope.scopeKey, scope.businessId);
    return res.json({
      demoMode: scope.businessId === 'kaveri_textiles',
      businessId: scope.businessId,
      graphType: 'evidence_knowledge_graph',
      nodes: graph.evidenceNodes,
      edges: graph.evidenceEdges,
      stats: graph.stats,
    });
  });

  app.get('/api/v1/graph/transactions', async (req, res) => {
    const proxied = await tryProxyPythonBackend('/api/v1/graph/transactions', 'GET');
    if (proxied) return res.status(proxied.status).json(proxied.data);
    const scope = resolveWorkspaceScope(req);
    const graph = getWorkspaceGraph(scope.scopeKey, scope.businessId);
    return res.json({
      demoMode: scope.businessId === 'kaveri_textiles',
      businessId: scope.businessId,
      graphType: 'financial_transaction_graph',
      nodes: graph.transactionNodes,
      edges: graph.transactionEdges,
      stats: graph.stats,
    });
  });

  // Stateless on-demand graph builder from client documents
  app.post('/api/v1/graph/build', (req, res) => {
    const docs = Array.isArray(req.body?.documents)
      ? (req.body.documents as EvidenceDocumentItem[])
      : [];
    const businessName =
      typeof req.body?.businessName === 'string' ? req.body.businessName : undefined;
    const businessId = typeof req.body?.businessId === 'string' ? req.body.businessId : undefined;
    const built = buildEvidenceGraphFromDocuments(docs, {
      fallbackBusinessName: businessName,
      fallbackBusinessId: businessId,
    });
    return res.json(built);
  });

  app.post('/api/v1/graph/detect-cycles', async (req, res) => {
    const proxied = await tryProxyPythonBackend('/api/v1/graph/detect-cycles', 'POST');
    if (proxied) return res.status(proxied.status).json(proxied.data);
    const scope = resolveWorkspaceScope(req);
    const graph = getWorkspaceGraph(scope.scopeKey, scope.businessId);
    const cycles = detectDirectedCycles(graph.transactionEdges, 4);
    return res.json({
      demoMode: scope.businessId === 'kaveri_textiles',
      engine: 'EvidenceOS-CycleDetector (NetworkX-compatible)',
      cycleCount: cycles.length,
      cycles,
    });
  });

  // Credit Assessment Endpoint
  app.post('/api/v1/credit/assess', async (req, res) => {
    const proxied = await tryProxyPythonBackend('/api/v1/credit/assess', 'POST', req.body);
    if (proxied) return res.status(proxied.status).json(proxied.data);
    const inputs = { ...KAVERI_BASELINE_FINANCIALS, ...(req.body?.inputs || {}) };
    const result = computeCreditAssessment(inputs, DEFAULT_CREDIT_WEIGHTS, 2, true);
    return res.json({ demoMode: true, assessment: result });
  });

  // Financial Stress Simulation Endpoint
  app.post('/api/v1/simulations/run', async (req, res) => {
    const proxied = await tryProxyPythonBackend('/api/v1/simulations/run', 'POST', req.body);
    if (proxied) return res.status(proxied.status).json(proxied.data);
    const scenarioType = req.body?.scenarioType || 'revenue_shock';
    const shockPercent = Number(req.body?.shockPercent ?? 20);
    const scaleVariableCostsWithRevenue = req.body?.scaleVariableCostsWithRevenue !== false;
    const sim = runFinancialStressSimulation(
      KAVERI_BASELINE_FINANCIALS,
      { scenarioType, shockPercent, scaleVariableCostsWithRevenue },
      true
    );
    return res.json({ demoMode: true, simulation: sim });
  });

  // AI Investigator Agent Endpoint
  app.post('/api/v1/investigations/:investigationId/query', async (req, res) => {
    try {
      const queryText = String(req.body?.query || '').trim();
      if (!queryText) {
        return res.status(400).json({ error: 'Investigation query cannot be empty.' });
      }
      if (queryText.length > 1000) {
        return res.status(400).json({ error: 'Investigation query exceeds 1000 character limit.' });
      }
      const mode =
        req.body?.mode === 'fast_lite' || req.body?.mode === 'search_grounded'
          ? req.body.mode
          : 'deep_thinking';

      const investigation = await runInvestigatorAgent({ query: queryText, mode });
      return res.json({ investigation });
    } catch (err) {
      const message = err instanceof Error ? err.message : 'AI Investigator failed.';
      return res.status(500).json({ error: message });
    }
  });

  // Multi-Agent AI Architecture Metadata & Connected EvidenceOS Stats
  app.get('/api/v1/multi-agent/architecture', (_req, res) => {
    return res.json({
      orchestratorVersion: 'evidenceos-multi-agent-v1',
      agentCount: AGENT_REGISTRY_METADATA.length,
      agents: AGENT_REGISTRY_METADATA,
      connectedInfrastructure: {
        graphEngine: 'NetworkX-compatible MultiDiGraph (src/utils/graphEngine.ts)',
        cycleDetector: 'Deterministic Directed Cycle Detector (src/utils/financialEngines.ts)',
        creditEngine: 'Deterministic 6-Factor Readiness Engine',
        aiModels: {
          fastStructured: OCR_LITE_MODEL,
          reasoning: REASONING_MODEL,
        },
        canonicalCounts: {
          documents: KAVERI_DOCUMENTS.length,
          evidenceNodes: KAVERI_EVIDENCE_NODES.length,
          evidenceEdges: KAVERI_EVIDENCE_EDGES.length,
          transactionEdges: KAVERI_TRANSACTION_EDGES.length,
          findings: KAVERI_FINDINGS.length,
        },
      },
      persistedRunsCount: listMultiAgentRuns().length,
    });
  });

  // Multi-Agent Orchestrated Investigation (Standard JSON response)
  app.post('/api/v1/multi-agent/investigate', async (req, res) => {
    try {
      const queryText = String(req.body?.query || '').trim();
      if (!queryText) {
        return res.status(400).json({ error: 'Investigation query cannot be empty.' });
      }
      if (queryText.length > 1000) {
        return res.status(400).json({ error: 'Investigation query exceeds 1000 character limit.' });
      }

      const runtime = {
        businessId: typeof req.body?.businessId === 'string' ? req.body.businessId : 'kaveri_textiles',
        documents: Array.isArray(req.body?.documents) ? req.body.documents : undefined,
        findings: Array.isArray(req.body?.findings) ? req.body.findings : undefined,
        financialBaseline:
          req.body?.financialBaseline && typeof req.body.financialBaseline === 'object'
            ? req.body.financialBaseline
            : undefined,
      };

      const run = await orchestrateMultiAgentInvestigation({ query: queryText, runtime });
      return res.json({ run });
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Multi-agent orchestration failed.';
      return res.status(500).json({ error: message });
    }
  });

  // Multi-Agent Orchestrated Investigation (Server-Sent Events real-time per-agent progress stream)
  app.post('/api/v1/multi-agent/investigate/stream', async (req, res) => {
    const queryText = String(req.body?.query || '').trim();
    if (!queryText) {
      return res.status(400).json({ error: 'Investigation query cannot be empty.' });
    }
    if (queryText.length > 1000) {
      return res.status(400).json({ error: 'Investigation query exceeds 1000 character limit.' });
    }

    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    res.flushHeaders?.();

    const writeEvent = (eventName: string, payload: unknown) => {
      res.write(`event: ${eventName}\ndata: ${JSON.stringify(payload)}\n\n`);
    };

    try {
      const runtime = {
        businessId: typeof req.body?.businessId === 'string' ? req.body.businessId : 'kaveri_textiles',
        documents: Array.isArray(req.body?.documents) ? req.body.documents : undefined,
        findings: Array.isArray(req.body?.findings) ? req.body.findings : undefined,
        financialBaseline:
          req.body?.financialBaseline && typeof req.body.financialBaseline === 'object'
            ? req.body.financialBaseline
            : undefined,
      };

      const run = await orchestrateMultiAgentInvestigation({
        query: queryText,
        runtime,
        onProgress: (evt) => writeEvent('progress', evt),
      });

      writeEvent('result', { run });
      res.end();
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Multi-agent orchestration failed.';
      writeEvent('error', { error: message });
      res.end();
    }
  });

  // Persisted Multi-Agent Execution History
  app.get('/api/v1/multi-agent/runs', (req, res) => {
    const businessId = typeof req.query.businessId === 'string' ? req.query.businessId : undefined;
    return res.json({ runs: listMultiAgentRuns(businessId) });
  });

  app.get('/api/v1/multi-agent/runs/:runId', (req, res) => {
    const run = getMultiAgentRunById(String(req.params.runId || ''));
    if (!run) {
      return res.status(404).json({ error: 'Multi-agent run not found.' });
    }
    return res.json({ run });
  });

  // Vite dev middleware or static dist serving
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.resolve(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`EvidenceOS server running on http://0.0.0.0:${PORT}`);
  });
}

startServer();
