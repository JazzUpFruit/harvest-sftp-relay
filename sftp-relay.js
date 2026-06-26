/* eslint-disable no-undef */
/**
 * SFTP Relay Service for Harvest Share EDI Hub
 */

const express = require('express');
const { Client } = require('ssh2');
const cors = require('cors');

const app = express();
app.use(express.json({ limit: '10mb' }));
app.use(cors());

const API_KEY = process.env.RELAY_API_KEY;

app.use((req, res, next) => {
  if (API_KEY && req.headers['x-api-key'] !== API_KEY) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  next();
});

app.post('/', (req, res) => {
  const { host, port, username, password, remote_path, content } = req.body;

  if (!host || !username || !remote_path || content === undefined) {
    return res.status(400).json({ error: 'host, username, remote_path, and content are required' });
  }

  const conn = new Client();
  let responded = false;

  const timeout = setTimeout(() => {
    if (!responded) {
      responded = true;
      conn.end();
      res.status(504).json({ error: 'SFTP upload timed out' });
    }
  }, 30000);

  conn.on('ready', () => {
    conn.sftp((err, sftp) => {
      if (err) {
        if (!responded) {
          responded = true;
          clearTimeout(timeout);
          conn.end();
          return res.status(500).json({ error: 'SFTP subsystem error: ' + err.message });
        }
      }

      const stream = sftp.createWriteStream(remote_path, { flags: 'w', mode: 0o644, autoClose: true });

      stream.on('error', (err) => {
        if (!responded) {
          responded = true;
          clearTimeout(timeout);
          conn.end();
          res.status(500).json({ error: 'Write error: ' + err.message });
        }
      });

      stream.on('close', () => {
        if (!responded) {
          responded = true;
          clearTimeout(timeout);
          conn.end();
          res.json({ success: true, remote_path: remote_path, bytes_written: Buffer.byteLength(content) });
        }
      });

      stream.end(Buffer.from(content));
    });
  });

  conn.on('error', (err) => {
    if (!responded) {
      responded = true;
      clearTimeout(timeout);
      res.status(500).json({ error: 'SSH connection error: ' + err.message });
    }
  });

  conn.connect({
    host,
    port: port || 22,
    username,
    password,
    readyTimeout: 20000,
    algorithms: {
      kex: ['ecdh-sha2-nistp256', 'ecdh-sha2-nistp384', 'ecdh-sha2-nistp521', 'diffie-hellman-group-exchange-sha256', 'diffie-hellman-group14-sha256', 'diffie-hellman-group14-sha1'],
      serverHostKey: ['ssh-rsa', 'ecdsa-sha2-nistp256', 'ssh-ed25519', 'rsa-sha2-256', 'rsa-sha2-512'],
      cipher: ['aes128-ctr', 'aes192-ctr', 'aes256-ctr', 'aes128-gcm', 'aes256-gcm'],
      hmac: ['hmac-sha2-256', 'hmac-sha2-512', 'hmac-sha1'],
    },
  });
});

app.post('/list-read', (req, res) => {
  const { host, port, username, password, remote_dir } = req.body;

  if (!host || !username || !remote_dir) {
    return res.status(400).json({ error: 'host, username, and remote_dir are required' });
  }

  const conn = new Client();
  let responded = false;

  const timeout = setTimeout(() => {
    if (!responded) {
      responded = true;
      conn.end();
      res.status(504).json({ error: 'SFTP list-read timed out' });
    }
  }, 60000);

  conn.on('ready', () => {
    conn.sftp((err, sftp) => {
      if (err) {
        if (!responded) {
          responded = true;
          clearTimeout(timeout);
          conn.end();
          return res.status(500).json({ error: 'SFTP subsystem error: ' + err.message });
        }
      }

      sftp.readdir(remote_dir, (err, list) => {
        if (err) {
          if (!responded) {
            responded = true;
            clearTimeout(timeout);
            conn.end();
            return res.status(500).json({ error: 'Read dir error: ' + err.message });
          }
        }

        const files = list.filter(f => f.filename && !f.filename.startsWith('.'));
        const results = [];
        let processed = 0;

        if (files.length === 0) {
          if (!responded) {
            responded = true;
            clearTimeout(timeout);
            conn.end();
            return res.json({ files: [] });
          }
        }

        files.forEach((fileEntry) => {
          const filePath = remote_dir.replace(/\/$/, '') + '/' + fileEntry.filename;

          sftp.readFile(filePath, 'utf8', (err, data) => {
            if (!err && data) {
              results.push({ name: fileEntry.filename, content: data });
            }

            processed++;
            if (processed === files.length && !responded) {
              responded = true;
              clearTimeout(timeout);
              conn.end();
              res.json({ files: results });
            }
          });
        });
      });
    });
  });

  conn.on('error', (err) => {
    if (!responded) {
      responded = true;
      clearTimeout(timeout);
      res.status(500).json({ error: 'SSH connection error: ' + err.message });
    }
  });

  conn.connect({
    host,
    port: port || 22,
    username,
    password,
    readyTimeout: 20000,
  });
});

app.get('/health', (req, res) => {
  res.json({ status: 'ok', service: 'sftp-relay' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`SFTP Relay running on port ${PORT}`);
});
