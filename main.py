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
	def is_port(str_):
		return str_.isdigit() and 1 <= int(str_) <= 65535

	istart, iend = int(start), int(end) + 1

	if is_port(start) and is_port(end) and istart <= iend:
		return range(istart, iend)

	raise ValueError


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

	response = await Scanner().scan_ports(ip, ports)
	return web.json_response(response)


if __name__ == '__main__':
	app = web.Application()
	app.add_routes(routes)

	logger.info('Launch tcpscan server')
	web.run_app(app, host='192.168.1.8', port=8080)
