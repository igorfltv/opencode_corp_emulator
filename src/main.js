import { createEmulator } from "./emulator.js";
const emulator = createEmulator({ port: Number(process.env.PORT ?? 4310) });
console.log(`Эмулятор: ${emulator.baseURL}/admin`);
console.log("Остановка: Ctrl+C");
process.on("SIGINT", () => { emulator.stop(); process.exit(0); });
process.on("SIGTERM", () => { emulator.stop(); process.exit(0); });
