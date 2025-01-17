/*
  Warnings:

  - The primary key for the `Session` table will be changed. If it partially fails, the table could be left without primary key constraint.
  - You are about to drop the column `createdAt` on the `Session` table. All the data in the column will be lost.
  - You are about to drop the column `sessionId` on the `Session` table. All the data in the column will be lost.
  - A unique constraint covering the columns `[sid]` on the table `Session` will be added. If there are existing duplicate values, this will fail.
  - Added the required column `data` to the `Session` table without a default value. This is not possible if the table is not empty.
  - Added the required column `sid` to the `Session` table without a default value. This is not possible if the table is not empty.

*/
-- DropForeignKey
ALTER TABLE "Session" DROP CONSTRAINT "Session_userId_fkey";

-- DropIndex
DROP INDEX "Session_sessionId_key";

-- AlterTable
ALTER TABLE "Session" DROP CONSTRAINT "Session_pkey",
DROP COLUMN "createdAt",
DROP COLUMN "sessionId",
ADD COLUMN     "data" TEXT NOT NULL,
ADD COLUMN     "sid" TEXT NOT NULL,
ALTER COLUMN "id" DROP DEFAULT,
ALTER COLUMN "id" SET DATA TYPE TEXT,
ALTER COLUMN "userId" DROP NOT NULL,
ADD CONSTRAINT "Session_pkey" PRIMARY KEY ("id");
DROP SEQUENCE "Session_id_seq";

-- CreateIndex
CREATE UNIQUE INDEX "Session_sid_key" ON "Session"("sid");

-- AddForeignKey
ALTER TABLE "Session" ADD CONSTRAINT "Session_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;
