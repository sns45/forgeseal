import { Hono } from "hono";

const app = new Hono();

app.get("/", (c) => c.text("Hello from forgeseal example"));

export default app;
