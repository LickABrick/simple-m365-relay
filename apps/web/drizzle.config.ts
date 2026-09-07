import { defineConfig } from 'drizzle-kit';
export default defineConfig({
	schema: './src/lib/server/schema.ts',
	out: './drizzle',
	dialect: 'sqlite',
	dbCredentials: { url: process.env.DATABASE_URL || '/tmp/simple-m365-relay.db' }
});
