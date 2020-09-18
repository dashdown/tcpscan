#!/usr/bin/env python3

from aiohttp import web
from ipaddress import ip_address

from asyncio import create_task, get_event_loop
from asyncio import Queue as IOQueue

from scanner import Scanner

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


async def request_worker():
	'''
	Запускает задачи scan_ports из очереди scan_requests.

	Результаты сканирования всех портов определенного хоста
	направляет в очередь scan_responses.
	'''
	scanner = Scanner()

	while True:
		ip_and_ports_to_scan = await scan_requests.get()
		logger.debug('Request worker getting new job')
		result = await scanner.scan_ports(*ip_and_ports_to_scan)

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
		await scan_requests.put(tuple([ip, ports]))

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
	web.run_app(app, host='192.168.1.8', port=8080)
