# Chat Application

A real-time chat application with file sharing capabilities (up to 80MB).

## Features

- User authentication (login/register)
- Real-time messaging
- File attachments (images, documents, etc.)
- Responsive design

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/chat-app.git
   cd chat-app
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Start the server:
   ```bash
   npm start
   ```

4. Access the application at `http://localhost:3000`

## Deployment

### Vercel

1. Install Vercel CLI:
   ```bash
   npm install -g vercel
   ```

2. Deploy:
   ```bash
   vercel
   ```

## Configuration

Create a `.env` file for environment variables:

```
AWS_ACCESS_KEY_ID=your_key
AWS_SECRET_ACCESS_KEY=your_secret
AWS_REGION=your_region
```

## License

MIT
