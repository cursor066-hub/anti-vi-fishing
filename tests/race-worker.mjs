import { workerData, parentPort } from 'node:worker_threads';
import { Fabric } from '../src/fabric.mjs';
let f;
try {
  f = new Fabric(workerData.config, workerData.directory, () => workerData.now);
  const output = workerData.runtime ? f.runtime.consume(workerData.principal, workerData.runtime) : f.execute(workerData.principal, workerData.certificate);
  parentPort.postMessage({ success: true, output });
} catch (e) { parentPort.postMessage({ success: false, code: e.code, message: e.message }); }
finally { if (f) f.close(); }
