# ApumaMart — Full Stack Repo

Website + Backend + Supabase + App ka complete code.

## Structure

```
apumamart-repo/
├── frontend/          # Website files (apumamart.com)
│   ├── subscribe-inject.js
│   └── supabase-connector.js
├── backend/           # API backend (api.apumamart.com)
│   ├── actions.js     # All 107 API actions
│   └── db.js          # Database setup
├── supabase/          # Supabase (future backend)
│   └── schema.sql     # 8 tables + RLS policies
└── docs/              # Guides
```

## Deploy

### Frontend → apumamart.com
Upload `frontend/*` to `public_html/`

### Backend → api.apumamart.com
Upload `backend/actions.js` to `hbuilds/last-source/routes/actions.js`
Upload `backend/db.js` to `hbuilds/last-source/db.js`
Then: hPanel → Redeploy

## Supabase
Project: https://pyvjqmgzwymutbjwtoxg.supabase.co
Schema: `supabase/schema.sql` (already applied)
