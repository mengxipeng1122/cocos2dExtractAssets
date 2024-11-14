import * as frida from 'frida';
import * as fs from 'fs';

export const connect_frida = async (
    app_name: string, 
    fridaScriptFile: string,
    init_cb?: (script: frida.Script) => void,
    message_cb?: (message: any) => void
    )=> {

  try {
      // Connect to device
      const device = await frida.getUsbDevice();
      console.log('Connected to device:', device.name);

      const scriptContent = fs.readFileSync(fridaScriptFile, 'utf8');

      // Get running processes
      const processes = await device.enumerateProcesses();
      
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
        message_cb && message_cb(message);
      });

      init_cb && init_cb(script);

      // Load script
      await script.load();
      console.log('Frida Script loaded successfully');

    //const ret = await script.exports.invoke_init();

  } catch (error) {
      console.error('Error:', error);
  }
}