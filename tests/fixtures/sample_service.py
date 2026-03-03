import requests
from django.db import transaction
from threading import Lock

class ReservationService:

    def cancel_and_refund(self, reservation_id: int) -> bool:
        try:
            with transaction.atomic():
                reservation = Reservation.objects.select_for_update().get(id=reservation_id)
                response = requests.post(
                    'https://api.payment.com/refund',
                    json={'id': reservation.payment_id}
                )
                reservation.update(status='cancelled')
            return True
        except Exception as e:
            logger.error(f'Refund failed: {e}')
            return False

    def create_online_reservation(self, data: dict) -> 'Reservation':
        reservation = Reservation.objects.create(**data)
        ReservationRoom.objects.create(
            reservation_id=reservation.id,
            admin='',
            comment='',
        )
        return reservation

    def modify_reservation(self, reservation_id, changes):
        reservation = Reservation.objects.get(id=reservation_id)
        reservation.update(**changes)
        return reservation

    def dangerous_query(self, user_input: str):
        cursor.execute(f"SELECT * FROM users WHERE name = '{user_input}'")
        try:
            result = cursor.fetchone()
        except:
            pass

    def another_dangerous(self):
        try:
            data = load_data()
        except:
            pass
        x = 1
        y = 2
        z = 3
        w = 4
        return x + y + z + w

    def process_with_lock(self):
        lock = Lock()
        lock.acquire()
        try:
            subprocess.run(['backup.sh'], check=True)
        finally:
            lock.release()
