# Database migrations

The schema is the source of truth. Use `npm run db:push` for the disposable demo database or create a reviewed migration before production deployment:

```bash
npx prisma migrate dev --name initial_nexus
npx prisma migrate deploy
```

Never run `db push` against a production database. Production deployments must run reviewed migrations, backups, and a rollback plan.
