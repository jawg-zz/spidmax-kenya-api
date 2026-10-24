import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import morgan from 'morgan';
import path from 'node:path';
import { deadlinesRouter } from './routes/deadlines';
import { fuelRouter } from './routes/fuel';

const app = express();

app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: false, crossOriginResourcePolicy: false }));
app.use(cors());
app.use(morgan(':method :url :status :response-time ms'));
app.use(express.json({ limit: '1mb' }));

app.get('/health', (_req, res) => {
  res.json({ ok: true, service: 'spidmax-kenya-api', version: process.env.APP_VERSION ?? '1.3.0' });
});

app.use('/v1/deadlines', deadlinesRouter);
app.use('/v1/fuel', fuelRouter);

// Release artifacts: /spidmax-kenya-1.3.0.apk and the stable /spidmax-kenya.apk
app.use(express.static(path.join(__dirname, '..', 'public'), { maxAge: '1h' }));

const port = Number(process.env.PORT ?? 3211);
app.listen(port, () => {
  // eslint-disable-next-line no-console
  console.log(`spidmax-kenya-api listening on ${port}`);
});
