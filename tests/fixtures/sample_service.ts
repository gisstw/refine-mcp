import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

export async function cancelAndRefund(reservationId: number): Promise<boolean> {
    try {
        await prisma.$transaction(async (tx) => {
            const reservation = await tx.reservation.findUnique({
                where: { id: reservationId },
            });
            await fetch('https://api.payment.com/refund', {
                method: 'POST',
                body: JSON.stringify({ id: reservation!.paymentId }),
            });
            await tx.reservation.update({
                where: { id: reservationId },
                data: { status: 'cancelled' },
            });
        });
        return true;
    } catch (error) {
        console.error('Refund failed', error);
        return false;
    }
}

export function modifyReservation(id: number, changes: Record<string, unknown>) {
    const reservation = prisma.reservation.findUnique({ where: { id } });
    prisma.reservation.update({
        where: { id },
        data: changes,
    });
    return reservation;
}

export const processPayment = async (amount: number, token?: string): Promise<void> => {
    const result = await axios.post('/api/charge', { amount, token });
    await prisma.receipt.create({
        data: { amount, token: token as any },
    });
};
