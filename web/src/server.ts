import express from 'express';
import path from 'path';
import fs from 'fs';
import { 
  LogEntry,
  TextureInfo,
  CompiledShader,
  app_name,
} from './common';
import { Server } from 'socket.io';
import { createServer } from 'http';

import * as frida from 'frida';

const app = express();
const port = 3000;

const fridaScriptFile = path.join(__dirname, '..', '..', 'frida', '_agent.js');


async function connect_frida() {

  try {
      // Connect to device
      const device = await frida.getUsbDevice();
      console.log('Connected to device:', device.name);

      const scriptContent = fs.readFileSync(fridaScriptFile, 'utf8');

      // Get running processes
      const processes = await device.enumerateProcesses();
      
      // Find your target app process (replace with your app's name)
      const targetProcess = processes.find(p => p.name.includes(app_name));
      
      if (!targetProcess) {
          throw new Error('Target process not found');
      }

      // Attach to the process
      const session = await device.attach(targetProcess.pid);
      console.log('Attached to process:', targetProcess.name);

      // Create script
      const script = await session.createScript(scriptContent);

      // Handle script messages
      script.message.connect((message: any) => {
          if (message.type === 'send') {
              const payload = message.payload;
              switch (payload.type) {
                  default:
                      console.log('Message from script:', message);
              }
          }
      });

      // Load script
      await script.load();
      console.log('Frida Script loaded successfully');

    //const ret = await script.exports.invoke_init();

  } catch (error) {
      console.error('Error:', error);
  }
}


// Serve static files from the dist/public directory instead of src/public
app.use(express.static(path.join(__dirname, '..', 'dist', 'public')));

// Function to monitor changes and reconnect Frida
function monitorFridaScript() {
  fs.watch(fridaScriptFile, (eventType, filename) => {
    if (eventType === 'change') {
      console.log(`Detected change in ${filename}, reconnecting Frida...`);
      connect_frida();
    }
  });
}

// Initial connect and start monitoring
connect_frida();
monitorFridaScript();

// Set up Socket.IO
const httpServer = createServer(app);

const io = new Server(httpServer, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"]
  }
});

io.on('connection', (socket) => {
  console.log('Client connected');

  socket.on('disconnect', () => {
    console.log('Client disconnected');
  });
});

// Use httpServer instead of app.listen
const server = httpServer;

server.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
}); 
