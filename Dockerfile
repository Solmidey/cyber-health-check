# syntax=docker/dockerfile:1.6

FROM node:20-slim

WORKDIR /work

# Prisma needs OpenSSL available in the container.
RUN apt-get update -y \
  && apt-get install -y --no-install-recommends openssl ca-certificates \
  && rm -rf /var/lib/apt/lists/*

# Corepack (pnpm)
RUN corepack enable

# Copy workspace manifests first (better caching)
COPY pnpm-lock.yaml pnpm-workspace.yaml package.json ./

# Copy API package manifests + prisma schema/migrations early for caching
COPY apps/api/package.json apps/api/package.json
COPY apps/api/prisma apps/api/prisma

# Install deps for the whole workspace
RUN pnpm install -r --frozen-lockfile

# Generate Prisma client (so runtime has a correct @prisma/client)
RUN pnpm -C apps/api prisma:generate

# Copy the rest of the API source code
COPY apps/api apps/api

WORKDIR /work/apps/api

EXPOSE 4000
