from asyncio import open_connection, wait_for
from asyncio import TimeoutError as IOTimeoutError
from asyncio import create_task
from asyncio import Queue as IOQueue

import logging


logger = logging.getLogger('tcpscan')


class Scanner:
	'''
	Сканер tcp-портов.
	'''
	def __init__(self, sockets_count=10, response_timeout=1):
		'''
		:param sockets_count: Количество сокетов используемое сканером.
		:param response_timeout: Сколько ждем ответа от хоста.
		'''
		self._response_timeout = response_timeout

		self._tasks = IOQueue()
		self._results = list()

		self._workers = list()

		for worker_id in range(sockets_count):
			worker = self._worker(
				worker_id,
				self._tasks,
				self._results)

			self._workers.append(create_task(worker))

	async def scan_ports(self, ip, ports):
		'''
		Сканирует tcp-порты в указанном промежутке.

		Сканирование производится методом handshake. Важно отметить,
		что если с хостом нет связи, то вернет ложно-отрицательный
		результат (порт на самом деле открыт, но скажет, что закрыт).

		:param ip: Строка вида '10.32.134.172'.
		:param ports: - задается, как range().
		:param sockets_count: Количество используемых сокетов.

		:returns: лист вида - [
			{'port': 1, 'state': 'open'},
			{'port': 2, 'state': 'close'}, ...
		]
		'''
		for port in ports:
			self._tasks.put_nowait((ip, port))

		await self._tasks.join()

		results = self._results.copy()
		self._results.clear()

		return results

	async def _check_tcp_port_openness(self, ip, port):
		try:
			await wait_for(
				open_connection(ip, port),
				self._response_timeout)

			return {'port': port, 'state': 'open'}

		except IOTimeoutError:
			return {'port': port, 'state': 'close'}

	async def _worker(self, worker_id, scan_tasks, results):
		name = f'Scan worker-{worker_id}'

		while True:
			ip, port = await scan_tasks.get()

			logger.debug(f'{name} getting job to scan {ip}:{port}')

			result = await self._check_tcp_port_openness(ip, port)
			results.append(result)
			scan_tasks.task_done()
			
			logger.debug(f'{name} finished job, result: {result}')
