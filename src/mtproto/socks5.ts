import { Socket } from 'net';

export interface SOCKS5Options {
  host: string;
  port: number;
  username?: string;
  password?: string;
  timeout?: number;
}

/**
 * Simple SOCKS5 client for testing proxy connectivity.
 * Connects to Telegram servers through SOCKS5 proxy.
 */
export class SOCKS5Client {
  private socket: Socket;
  private connected: boolean = false;

  constructor(private options: SOCKS5Options) {
    this.socket = new Socket();
  }

  /**
   * Connect to SOCKS5 proxy and authenticate.
   */
  async connect(): Promise<void> {
    const { host, port, username, password, timeout = 10000 } = this.options;

    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.socket.destroy();
        reject(new Error('Connection timeout'));
      }, timeout);

      this.socket.on('error', (err) => {
        clearTimeout(timer);
        reject(err);
      });

      this.socket.connect(port, host, () => {
        clearTimeout(timer);

        // SOCKS5 handshake
        const authMethods = username && password ? [0x00, 0x02] : [0x00]; // No auth or Username/Password
        const handshake = Buffer.from([
          0x05, // SOCKS version 5
          authMethods.length, // Number of methods
          ...authMethods,
        ]);

        this.socket.write(handshake);

        this.socket.once('data', async (data) => {
          try {
            // Check SOCKS5 response
            if (data[0] !== 0x05) {
              throw new Error('Invalid SOCKS5 response');
            }

            const authMethod = data[1];

            // If username/password auth required
            if (authMethod === 0x02) {
              if (!username || !password) {
                throw new Error('Authentication required but not provided');
              }

              await this.authenticate(username, password);
            } else if (authMethod === 0x00) {
              // No authentication required
              this.connected = true;
            } else {
              throw new Error('Unsupported authentication method');
            }

            resolve();
          } catch (err) {
            this.socket.destroy();
            reject(err);
          }
        });
      });
    });
  }

  /**
   * Authenticate with username/password.
   */
  private async authenticate(username: string, password: string): Promise<void> {
    return new Promise((resolve, reject) => {
      const userBuf = Buffer.from(username, 'utf8');
      const passBuf = Buffer.from(password, 'utf8');

      const authPacket = Buffer.concat([
        Buffer.from([0x01]), // Auth version
        Buffer.from([userBuf.length]),
        userBuf,
        Buffer.from([passBuf.length]),
        passBuf,
      ]);

      this.socket.write(authPacket);

      this.socket.once('data', (data) => {
        if (data[0] === 0x01 && data[1] === 0x00) {
          this.connected = true;
          resolve();
        } else {
          this.socket.destroy();
          reject(new Error('Authentication failed'));
        }
      });
    });
  }

  /**
   * Test connection by connecting to Telegram server through SOCKS5.
   *
   * @returns True if connection successful
   */
  async testConnection(): Promise<boolean> {
    if (!this.connected) {
      throw new Error('Not connected to SOCKS5 proxy');
    }

    return new Promise((resolve) => {
      // Connect to Telegram server
      const telegramHost = '149.154.167.50'; // DC 2
      const telegramPort = 443;

      const hostBuf = Buffer.from(telegramHost, 'utf8');
      const connectCmd = Buffer.concat([
        Buffer.from([
          0x05, // SOCKS version
          0x01, // Connect command
          0x00, // Reserved
          0x03, // Domain name
          hostBuf.length, // Domain length
        ]),
        hostBuf,
        Buffer.from([
          (telegramPort >> 8) & 0xff, // Port high byte
          telegramPort & 0xff, // Port low byte
        ]),
      ]);

      this.socket.write(connectCmd);

      this.socket.once('data', (data) => {
        // Check SOCKS5 response
        if (data[0] === 0x05 && data[1] === 0x00) {
          // Success
          resolve(true);
        } else {
          resolve(false);
        }
      });

      setTimeout(() => resolve(false), 5000);
    });
  }

  /**
   * Close the connection.
   */
  close(): void {
    if (this.socket) {
      this.socket.destroy();
      this.connected = false;
    }
  }
}
