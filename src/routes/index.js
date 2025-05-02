import userRouter from "./userRouter.js"
import uploadRouter from "./uploadRouter.js"

const routes = (app) => {
  app.use("/api/user", userRouter);
  app.use("/api/upload", uploadRouter);
};

export default routes;
