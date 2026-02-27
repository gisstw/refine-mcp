<?php
namespace App\Services;

class SampleService
{
    public function cancelAndRefund(int $reservationId): bool
    {
        try {
            DB::transaction(function () use ($reservationId) {
                $reservation = Reservation::lockForUpdate()->find($reservationId);
                $this->paymentService->refundPayment($reservation);
                $reservation->update(['status' => '9']);
            });
            return true;
        } catch (\Exception $e) {
            Log::error('Refund failed', ['id' => $reservationId]);
            return false;
        }
    }

    public function createOnlineReservation(array $data): Reservation
    {
        $reservation = Reservation::create($data);
        $room = Reservation_room::create([
            'reservation_id' => $reservation->id,
            'admin' => '',
            'comment' => '',
        ]);
        event(new ReservationCreated($reservation));
        return $reservation;
    }

    public function modifyReservation(int $id, array $changes)
    {
        $reservation = Reservation::find($id);
        if ($reservation->status === '9') {
            return false;
        }
        $reservation->update($changes);
        return $reservation;
    }
}
