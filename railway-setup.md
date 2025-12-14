# Alternative Database Setup

If Supabase doesn't work with Vercel, use Railway:

1. Go to https://railway.app
2. Create new project → PostgreSQL
3. Get connection string from Railway dashboard
4. Update DATABASE_URL in Vercel environment variables

Railway connection format:
postgresql://postgres:password@host:port/database

Your current Supabase data can be exported and imported to Railway if needed.