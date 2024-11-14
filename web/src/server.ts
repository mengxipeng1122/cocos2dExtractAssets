import express from 'express';
import path from 'path';

import { 
  app_name,
} from './common';

import { createServer } from 'http';
import { connect_frida } from './utils';

const app = express();
const port = 3000;

const fridaScriptFile = path.join(__dirname, '..', '..', 'frida', '_agent.js');

// Serve static files from the dist/public directory instead of src/public
app.use(express.json());  // for parsing application/json
// app.use(express.urlencoded({ extended: true }));  // for parsing application/x-www-form-urlencoded
app.use(express.static(path.join(__dirname, '..', 'dist', 'public')));


connect_frida(app_name, fridaScriptFile, (script) => {

  // add a route to invoke frida functions
  app.post('/api/invoke_frida_function', async (req, res) => {
    const { fun, arg } = await req.body;
    const result = await script.exports.invoke_frida_function(fun, arg);
    if (result instanceof Buffer) {
      res.setHeader('Content-Type', 'application/octet-stream');
      res.send(result);
    } else {
      res.setHeader('Content-Type', 'application/json');
      res.json(result);
    }
  });

  console.log('Frida script loaded');
});

// Set up Socket.IO
const httpServer = createServer(app);

// Use httpServer instead of app.listen
const server = httpServer;

server.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
}); 
