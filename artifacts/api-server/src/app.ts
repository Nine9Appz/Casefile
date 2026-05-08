import cors from "cors";
import express, { type Express } from "express";
import pinoHttp from "pino-http";
import { logger } from "./lib/logger";
import { errorHandler } from "./middlewares/error-handler";
import router from "./routes";

const app: Express = express();

app.use(
  pinoHttp({
    logger,
    serializers: {
      req(req) {
        return {
          id: req.id,
          method: req.method,
          url: req.url?.split("?")[0],
        };
      },
      res(res) {
        return {
          statusCode: res.statusCode,
        };
      },
    },
  }),
);
app.use(cors());
// 12mb headroom — handlers enforce a tighter 10mb limit on artifact content.
app.use(express.json({ limit: "12mb" }));
app.use(express.urlencoded({ extended: true, limit: "12mb" }));

app.use("/api", router);

app.use(errorHandler);

export default app;
