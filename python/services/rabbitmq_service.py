import json
import os
import aio_pika
import logging
from typing import Optional, Dict, Any

logger = logging.getLogger("sentineltrust.rabbitmq")

RABBITMQ_HOST = os.getenv("RABBITMQ_HOST", "localhost")
RABBITMQ_PORT = int(os.getenv("RABBITMQ_PORT", "5672"))
RABBITMQ_USER = os.getenv("RABBITMQ_USER", "guest")
RABBITMQ_PASSWORD = os.getenv("RABBITMQ_PASSWORD", "guest")

connection: Optional[aio_pika.RobustConnection] = None
channel: Optional[aio_pika.RobustChannel] = None
exchange: Optional[aio_pika.RobustExchange] = None

async def init_rabbitmq():
    global connection, channel, exchange
    try:
        connection = await aio_pika.connect_robust(
            host=RABBITMQ_HOST,
            port=RABBITMQ_PORT,
            login=RABBITMQ_USER,
            password=RABBITMQ_PASSWORD
        )
        channel = await connection.channel()
        exchange = await channel.declare_exchange(
            "sentineltrust.security",
            aio_pika.ExchangeType.TOPIC,
            durable=True
        )

        # Declare DLQ & Quarantine queues
        dlq = await channel.declare_queue("sentineltrust.dlq", durable=True)
        quarantine_queue = await channel.declare_queue("sentineltrust.quarantine.queue", durable=True)
        await quarantine_queue.bind(exchange, routing_key="threat.quarantine.*")

        audit_queue = await channel.declare_queue("sentineltrust.audit.queue", durable=True)
        await audit_queue.bind(exchange, routing_key="threat.audit.*")

        logger.info("RabbitMQ exchange 'sentineltrust.security' and queues declared.")
    except Exception as e:
        logger.warning(f"RabbitMQ connection warning: {e}. Continuing in resilient mode.")

async def publish_threat_event(routing_key: str, event: Dict[str, Any]):
    global exchange
    if exchange is not None:
        try:
            message = aio_pika.Message(
                body=json.dumps(event).encode("utf-8"),
                delivery_mode=aio_pika.DeliveryMode.PERSISTENT,
                content_type="application/json"
            )
            await exchange.publish(message, routing_key=routing_key)
        except Exception as e:
            logger.error(f"Failed to publish to RabbitMQ: {e}")

async def close_rabbitmq():
    global connection, channel
    if channel and not channel.is_closed:
        try:
            await channel.close()
        except Exception:
            pass
    if connection and not connection.is_closed:
        try:
            await connection.close()
        except Exception:
            pass
