import { rm } from "node:fs/promises";

const generatedDirectories = [
  new URL("../dist/client/", import.meta.url),
  new URL("../dist/server/", import.meta.url),
  new URL("../dist/.openai/", import.meta.url),
];

await Promise.all(
  generatedDirectories.map((directory) =>
    rm(directory, { recursive: true, force: true }),
  ),
);
