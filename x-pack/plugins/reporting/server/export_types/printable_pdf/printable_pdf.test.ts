/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import * as Rx from 'rxjs';
import { coreMock, elasticsearchServiceMock, loggingSystemMock } from '@kbn/core/server/mocks';
import { Writable } from 'stream';
import { CancellationToken } from '@kbn/reporting-common';
import { generatePdfObservable } from './lib/generate_pdf';
import { cryptoFactory } from '../../lib/crypto';
import { TaskPayloadPDF } from './types';
import { PdfV1ExportType } from './printable_pdf';
import { ScreenshottingStart } from '@kbn/screenshotting-plugin/server';
import { createMockConfigSchema, createMockReportingCore } from '../../test_helpers';

jest.mock('./lib/generate_pdf');

let content: string;
let mockPdfExportType: PdfV1ExportType;
let stream: jest.Mocked<Writable>;

const cancellationToken = {
  on: jest.fn(),
} as unknown as CancellationToken;

const mockLogger = loggingSystemMock.createLogger();

const mockEncryptionKey = 'testencryptionkey';
const encryptHeaders = async (headers: Record<string, string>) => {
  const crypto = cryptoFactory(mockEncryptionKey);
  return await crypto.encrypt(headers);
};

const getBasePayload = (baseObj: any) => baseObj as TaskPayloadPDF;

beforeEach(async () => {
  content = '';
  stream = { write: jest.fn((chunk) => (content += chunk)) } as unknown as typeof stream;
  const configType = createMockConfigSchema({ encryptionKey: mockEncryptionKey });
  const context = coreMock.createPluginInitializerContext(configType);

  const mockCoreSetup = coreMock.createSetup();
  const mockCoreStart = coreMock.createStart();
  const mockReportingCore = await createMockReportingCore(createMockConfigSchema());

  mockPdfExportType = new PdfV1ExportType(mockCoreSetup, configType, mockLogger, context);

  mockPdfExportType.setup({
    basePath: { set: jest.fn() },
  });
  mockPdfExportType.start({
    esClient: elasticsearchServiceMock.createClusterClient(),
    savedObjects: mockCoreStart.savedObjects,
    uiSettings: mockCoreStart.uiSettings,
    screenshotting: {} as unknown as ScreenshottingStart,
    reporting: mockReportingCore.getContract(),
  });
});

afterEach(() => (generatePdfObservable as jest.Mock).mockReset());

test(`passes browserTimezone to generatePdf`, async () => {
  const encryptedHeaders = await encryptHeaders({});
  (generatePdfObservable as jest.Mock).mockReturnValue(Rx.of({ buffer: Buffer.from('') }));

  const browserTimezone = 'UTC';
  await mockPdfExportType.runTask(
    'pdfJobId',
    getBasePayload({
      title: 'PDF Params Timezone Test',
      relativeUrl: '/app/kibana#/something',
      browserTimezone,
      headers: encryptedHeaders,
    }),
    cancellationToken,
    stream
  );

  expect(generatePdfObservable).toHaveBeenCalledWith(
    expect.anything(),
    expect.objectContaining({ browserTimezone: 'UTC' })
  );
});

test(`returns content_type of application/pdf`, async () => {
  const encryptedHeaders = await encryptHeaders({});

  (generatePdfObservable as jest.Mock).mockReturnValue(Rx.of({ buffer: Buffer.from('') }));

  const { content_type: contentType } = await mockPdfExportType.runTask(
    'pdfJobId',
    getBasePayload({ objects: [], headers: encryptedHeaders }),
    cancellationToken,
    stream
  );
  expect(contentType).toBe('application/pdf');
});

test(`returns content of generatePdf getBuffer base64 encoded`, async () => {
  const testContent = 'test content';
  (generatePdfObservable as jest.Mock).mockReturnValue(Rx.of({ buffer: Buffer.from(testContent) }));

  const encryptedHeaders = await encryptHeaders({});
  await mockPdfExportType.runTask(
    'pdfJobId',
    getBasePayload({ objects: [], headers: encryptedHeaders }),
    cancellationToken,
    stream
  );

  expect(content).toEqual(testContent);
});
