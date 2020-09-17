#!/usr/bin/env python3

from aiohttp import web
from ipaddress import ip_address

from asyncio import open_connection, wait_for
from asyncio import TimeoutError as IOTimeoutError
from asyncio import create_task, get_event_loop
from asyncio import Queue as IOQueue

import logging, logging.handlers


logger = logging.getLogger('tcpscan')
handler = logging.handlers.SysLogHandler(address='/dev/log')

logger.setLevel(logging.DEBUG)
logger.addHandler(handler)

routes = web.RouteTableDef()


def port_range(start, end):
	'''
	Если промежуток портов указан корректно, вернет range(start, end).

	В случае, если порты заданы с ошибкой, вызывает ValueError.

	:param start: Начало промежутка портов.
	:param end: Конец промежутка.

	:returns: range(start, end)
	'''
	is_port = lambda str_: str_.isdigit() and 1 <= int(str_) <= 65535
	istart, iend = int(start), int(end) + 1

	if is_port(start) and is_port(end) and istart <= iend:
		return range(istart, iend)
	
	raise ValueError


async def scan_worker(index, queue, result):
	'''
	Выполняет задачи из queue по сканированию tcp-портов.

	Результаты сканирования направляет в лист result.
	'''
	name = f'Scan worker-{index}'

	while True:
		ip, port = await queue.get()

		logger.debug(f'{name} getting job to scan {ip}:{port}')
		result.append(await scan_port(ip, port))
		queue.task_done()
		logger.debug(f'{name} finished job')


async def scan_port(ip, port, timeout=1):
	'''
	Сканирует конкретный tcp-порт. 

	Сканирование производится методом handshake. Важно отметить,
	что если с хостом нет связи, то вернет ложно-отрицательный
	результат (порт на самом деле открыт, но скажет, что закрыт).

	:param ip: Строка вида '10.32.134.172'.
	:param ports: Конкретный сканируемый порт.

	:returns: словарь вида - {'port': 1, 'state': 'open/close'}
	'''
	try:
		logger.debug(f'Scan port[{port}]')
		await wait_for(open_connection(ip, port), timeout)
	
	except IOTimeoutError:
		return {'port': port, 'state': 'close'}
	
	else:
		return {'port': port, 'state': 'open'}


async def scan_ports(ip, ports, scanners_count=1000):
	'''
	Сканирует tcp-порты в указанном промежутке.

	:param ip: Строка вида '10.32.134.172'.
	:param ports: - задается, как range().
	:param scanners_count: Количество сканеров, выполняющих запросы.

	:returns: лист вида - [
		{'port': 1, 'state': 'open'}, 
		{'port': 2, 'state': 'close'}, ...
	]
	'''
	queue = IOQueue()
	for port in ports:
		queue.put_nowait(tuple([ip, port]))

	result = list()

	workers = [scan_worker(i, queue, result) for i in range(scanners_count)]
	tasks = [create_task(worker) for worker in workers]

	logger.debug(f'Host[{ip}:{ports}] scan task start')
	await queue.join()
	for task in tasks: task.cancel()
	logger.debug(f'Host[{ip}:{ports}] scan task finished')

	return result


async def request_worker():
	'''
	Запускает задачи scan_ports из очереди scan_requests.

	Результаты сканирования всех портов определенного хоста
	направляет в очередь scan_responses.
	'''
	while True:
		scan_ports_task = await scan_requests.get()
		logger.debug('Request worker getting new job')
		result = await scan_ports_task

		scan_requests.task_done()
		logger.debug('Request worker finished job')
		scan_responses.put_nowait(result)


@routes.get('/scan/{ip}/{start_port}/{end_port}')
async def request_handler(request):
	'''
	Запускает поиск открытых tcp-портов для указанного хоста. 
	'''
	info = request.match_info
	peername = request.transport.get_extra_info('peername')

	logger.info(f'Handle request to scan {info} from {peername}')

	try:
		ip = str(ip_address(info['ip']))
		ports = port_range(info['start_port'], info['end_port'])

	except ValueError:
		logger.debug(f'Invalid request {info} from {peername}')
		return web.Response(text=f'Invalid IP or ports range')

	else:
		await scan_requests.put(scan_ports(ip, ports))

		if scan_requests.full():
			logger.warning(f'Requests limit reached')

		response = await scan_responses.get()
		logger.debug(f'Send result scan {ip}:{ports} to {peername}')
		return web.json_response(response)


if __name__ == '__main__':
	scan_requests = IOQueue(maxsize=10)
	scan_responses = IOQueue()

	loop = get_event_loop()
	loop.create_task(request_worker())

	app = web.Application()
	app.add_routes(routes)

	logger.info('Launch tcpscan server')
	web.run_app(app, host='192.168.1.10', port=8080)
