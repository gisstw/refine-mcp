use sqlx::MySqlPool;
use anyhow::Result;

pub async fn cancel_reservation(pool: &MySqlPool, id: u32) -> Result<()> {
    let mut tx = pool.begin().await?;
    let reservation = sqlx::query_as!(
        Reservation,
        "SELECT * FROM reservations WHERE id = ? FOR UPDATE",
        id
    )
    .fetch_one(&mut *tx)
    .await?;
    sqlx::query!("UPDATE reservations SET status = '9' WHERE id = ?", id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(())
}

pub async fn create_reservation(pool: &MySqlPool, data: &ReservationData) -> Result<Reservation> {
    let result = sqlx::query!("INSERT INTO reservations (arrival, departure) VALUES (?, ?)")
        .execute(pool)
        .await?;
    Ok(Reservation {
        id: result.last_insert_id() as u32,
    })
}

pub fn calculate_total(items: &[LineItem]) -> Decimal {
    items.iter().map(|i| i.amount).sum()
}

pub async fn risky_update(pool: &MySqlPool, id: u32) -> Result<()> {
    let row = sqlx::query!("SELECT * FROM reservations WHERE id = ?", id)
        .fetch_one(pool)
        .await?;
    sqlx::query!("UPDATE reservations SET status = '1' WHERE id = ?", id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn with_error_handling(pool: &MySqlPool) -> Result<()> {
    match do_something().await {
        Ok(v) => process(v),
        Err(e) => {
            tracing::error!("failed: {e}");
            return Ok(());
        }
    }
    let data = fetch_external_api().await.unwrap();
    Ok(())
}
