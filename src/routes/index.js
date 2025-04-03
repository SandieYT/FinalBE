import userRouter from "./userRouter.js"

const routes = (app) => {
  app.use("/api/user", userRouter);
};

export default routes;
