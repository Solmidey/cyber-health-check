-- CreateEnum
CREATE TYPE "NotificationMode" AS ENUM ('immediate', 'digest');

-- CreateTable
CREATE TABLE "NotificationRule" (
    "id" TEXT NOT NULL,
    "tenantId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "enabled" BOOLEAN NOT NULL DEFAULT true,
    "mode" "NotificationMode" NOT NULL DEFAULT 'immediate',
    "minRisk" INTEGER,
    "verdicts" TEXT[],
    "eventTypes" TEXT[],
    "hostAllow" TEXT[],
    "hostDeny" TEXT[],
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "NotificationRule_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "NotificationRuleChannel" (
    "ruleId" TEXT NOT NULL,
    "channelId" TEXT NOT NULL,

    CONSTRAINT "NotificationRuleChannel_pkey" PRIMARY KEY ("ruleId","channelId")
);

-- CreateIndex
CREATE INDEX "NotificationRule_tenantId_enabled_idx" ON "NotificationRule"("tenantId", "enabled");

-- CreateIndex
CREATE INDEX "NotificationRule_tenantId_createdAt_idx" ON "NotificationRule"("tenantId", "createdAt");

-- CreateIndex
CREATE INDEX "NotificationRuleChannel_channelId_idx" ON "NotificationRuleChannel"("channelId");

-- AddForeignKey
ALTER TABLE "NotificationRule" ADD CONSTRAINT "NotificationRule_tenantId_fkey" FOREIGN KEY ("tenantId") REFERENCES "Tenant"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "NotificationRuleChannel" ADD CONSTRAINT "NotificationRuleChannel_ruleId_fkey" FOREIGN KEY ("ruleId") REFERENCES "NotificationRule"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "NotificationRuleChannel" ADD CONSTRAINT "NotificationRuleChannel_channelId_fkey" FOREIGN KEY ("channelId") REFERENCES "NotificationChannel"("id") ON DELETE CASCADE ON UPDATE CASCADE;
