/*
  Warnings:

  - A unique constraint covering the columns `[token,userId]` on the table `Session` will be added. If there are existing duplicate values, this will fail.

*/
-- CreateIndex
CREATE UNIQUE INDEX "Session_token_userId_key" ON "Session"("token", "userId");
