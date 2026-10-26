// Development-only independent PostgreSQL engine and TLS frontend. All listeners are loopback.
// Existing test dependencies must be supplied via NODE_PATH; this script installs nothing.
import path from 'node:path';
import {pathToFileURL} from 'node:url';
import net from 'node:net';
import tls from 'node:tls';
import fs from 'node:fs';
const modules=process.env.NODE_PATH;
if(!modules)throw Error('Set NODE_PATH to the installed test modules directory');
const {PGlite}=await import(pathToFileURL(path.join(modules,'@electric-sql/pglite/dist/index.js')));
const {PGLiteSocketServer}=await import(pathToFileURL(path.join(modules,'@electric-sql/pglite-socket/dist/index.js')));
const root=process.argv[2];const port=Number(process.argv[3]);const tlsPort=Number(process.argv[4]);
const db=await PGlite.create();const backend=new PGLiteSocketServer({db,port,host:'127.0.0.1',maxConnections:1});await backend.start();
const secureContext=tls.createSecureContext({key:fs.readFileSync(path.join(root,'local-key.pem')),cert:fs.readFileSync(path.join(root,'local-cert.pem'))});
const frontend=net.createServer(socket=>{
  let bytes=Buffer.alloc(0);
  function request(data){bytes=Buffer.concat([bytes,data]);if(bytes.length<8)return;socket.removeListener('data',request);if(bytes.length!==8||bytes.readUInt32BE(0)!==8||bytes.readUInt32BE(4)!==80877103){socket.destroy();return;}
    socket.write('S');const secure=new tls.TLSSocket(socket,{isServer:true,secureContext,ALPNProtocols:['postgresql']});const remote=net.connect(port,'127.0.0.1');secure.pipe(remote).pipe(secure);secure.on('error',()=>remote.destroy());remote.on('error',()=>secure.destroy());secure.on('close',()=>remote.destroy());remote.on('close',()=>secure.destroy());
  }
  socket.setTimeout(15000,()=>socket.destroy());socket.on('error',()=>{});socket.on('data',request);
});
frontend.listen(tlsPort,'127.0.0.1',()=>console.log('ready'));
