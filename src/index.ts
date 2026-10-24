import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import morgan from 'morgan';
import path from 'node:path';
import { deadlinesRouter } from './routes/deadlines';
import { fuelRouter } from './routes/fuel';
import { adminRouter } from './routes/admin';

const app = express();

app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: false, crossOriginResourcePolicy: false }));
app.use(cors());
app.use(morgan(':method :url :status :response-time ms'));
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: false }));
app.disable('x-powered-by');

// Admin surface: no framing, no external assets, never cached.
app.use((req, res, next) => {
  if (req.path.startsWith('/admin') || req.path.startsWith('/api/admin')) {
    res.setHeader('Cache-Control', 'no-store, max-age=0');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('Content-Security-Policy',
      "default-src 'none'; style-src 'unsafe-inline'; script-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'");
  }
  next();
});

app.get('/health', (_req, res) => {
  res.json({ ok: true, service: 'spidmax-kenya-api', version: process.env.APP_VERSION ?? '1.3.0' });
});

app.use('/v1/deadlines', deadlinesRouter);
app.use('/v1/fuel', fuelRouter);

// Admin console (token login, cookie session)
app.use(adminRouter);

// Release artifacts: /spidmax-kenya-1.3.0.apk and the stable /spidmax-kenya.apk
app.use(express.static(path.join(__dirname, '..', 'public'), { maxAge: '1h' }));

const port = Number(process.env.PORT ?? 3211);
app.listen(port, () => {
  // eslint-disable-next-line no-console
  console.log(`spidmax-kenya-api listening on ${port}`);
});
