# syntax=docker/dockerfile:1.6
FROM node:20-slim

WORKDIR /work

ENV CI=true
ENV COREPACK_ENABLE_DOWNLOAD_PROMPT=0

RUN corepack enable

# Copy workspace manifests first (better cache)
COPY pnpm-lock.yaml pnpm-workspace.yaml package.json ./
COPY apps/api/package.json apps/api/package.json

# Prisma schema + migrations MUST be present before generate
COPY apps/api/prisma apps/api/prisma

# Install deps (workspace-aware)
RUN pnpm install -r --frozen-lockfile

# Generate Prisma Client (this is the missing piece)
RUN pnpm -C apps/api prisma:generate

# Copy the rest of the API app
COPY apps/api apps/api

WORKDIR /work/apps/api

ENV NODE_ENV=production
ENV PORT=4000