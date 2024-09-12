import NextAuth from 'next-auth';
import { authConfig } from './auth.config';
import Credentials from 'next-auth/providers/credentials';
import { z } from 'zod';
import { sql } from '@vercel/postgres';
import type { User } from '@/app/lib/definitions';
import bcrypt from 'bcrypt';

async function getUser(email: string): Promise<User | undefined> {
  try {
    const user = await sql<User>`SELECT * FROM users WHERE email=${email}`;
    return user.rows[0];
  } catch (error) {
    console.error('Failed to fetch user:', error);
    throw new Error('Failed to fetch user.');
  }
}
 
export const { auth, signIn, signOut } = NextAuth({
  ...authConfig,
  providers: [
    Credentials({
      async authorize(credentials) {
        const parsedCredentials = z
          .object({ email: z.string().email(), password: z.string().min(6) })
          .safeParse(credentials);

          if (parsedCredentials.success) {
            const { email, password } = parsedCredentials.data;
            const user = await getUser(email);
            if (!user) return null;
            const passwordsMatch = await bcrypt.compare(password, user.password);

            if (passwordsMatch) return user;
          }

          console.log('Invalid credentials');
          return null;
      },
    }),
  ],
});

// Note: This configuration issue is not in this file.
// To resolve this, you need to check two locations:

// 1. In your .env file:
//    Look for AUTH_URL or NEXTAUTH_URL
//    If it includes a path like "/api/auth", consider removing it.
//    Example: Change from "http://localhost:3000/api/auth" to "http://localhost:3000"

// 2. In your auth.config.ts file:
//    Check if there's a basePath property in the configuration.
//    If present, consider removing it.

// Ensure only one of these configurations (AUTH_URL path or basePath) is used, not both.