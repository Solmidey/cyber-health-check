-- AlterEnum
ALTER TYPE "NotificationDeliveryStatus" ADD VALUE 'skipped';

-- CreateTable
CREATE TABLE "NotificationSuppression" (
    "id" TEXT NOT NULL,
    "tenantId" TEXT NOT NULL,
    "hostname" TEXT NOT NULL,
    "mutedUntil" TIMESTAMP(3) NOT NULL,
    "reason" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "NotificationSuppression_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "NotificationSuppression_tenantId_mutedUntil_idx" ON "NotificationSuppression"("tenantId", "mutedUntil");

-- CreateIndex
CREATE UNIQUE INDEX "NotificationSuppression_tenantId_hostname_key" ON "NotificationSuppression"("tenantId", "hostname");

-- AddForeignKey
ALTER TABLE "NotificationSuppression" ADD CONSTRAINT "NotificationSuppression_tenantId_fkey" FOREIGN KEY ("tenantId") REFERENCES "Tenant"("id") ON DELETE CASCADE ON UPDATE CASCADE;
