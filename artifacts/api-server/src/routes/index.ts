import { Router, type IRouter } from "express";
import artifactsRouter from "./artifacts";
import casesRouter from "./cases";
import healthRouter from "./health";
import stepsRouter from "./steps";

const router: IRouter = Router();

router.use(healthRouter);
router.use(casesRouter);
router.use(artifactsRouter);
router.use(stepsRouter);

export default router;
