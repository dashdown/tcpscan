#!/usr/bin/env python3

from aiohttp import web
from ipaddress import ip_address

from asyncio import open_connection, wait_for
from asyncio import TimeoutError as ATimeoutError
from asyncio import gather


# http://192.168.1.10:8080/scan/95.142.39.186/1/550
# http://192.168.1.10:8080/scan/198.12.250.43/1/550


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


async def scan_port(ip, port, timeout=1):
	'''
	Сканирует конкретный tcp-порт. 

	Сканирование производится методом handshake. Важно отметить,
	что если с хостом нет связи, то вернет ложно-отрицательный
	результат (порт на самом деле открыт, но скажет, что закрыт).

	:param ip: Строка вида '10.32.134.172'.
	:param ports: - задается, как range().

	:returns: словарь вида - {'port': 1, 'state': 'open/close'}
	'''
	try:
		await wait_for(open_connection(ip, port), timeout)
	
	except ATimeoutError:
		return {'port': port, 'state': 'close'}
	
	else:
		return {'port': port, 'state': 'open'}


async def scan_host_ports(ip, ports):
	'''
	Сканирует tcp-порты в указанном промежутке.

	Использует вызов scan_port.

	:param ip: Строка вида '10.32.134.172'.
	:param ports: - задается, как range().

	:returns: лист вида - [
		{'port': 1, 'state': 'open'}, 
		{'port': 2, 'state': 'close'}, ...
	]
	'''
	scans = [scan_port(ip, port) for port in ports]
	result = await gather(*scans)

	return result


@routes.get('/scan/{ip}/{start_port}/{end_port}')
async def scan_request_handle(request):
	'''
	Запускает поиск открытых tcp-портов для указанного хоста. 
	'''
	info = request.match_info

	try:
		ip = str(ip_address(info['ip']))
		ports = port_range(info['start_port'], info['end_port'])
		result = await scan_host_ports(ip, ports)

		return web.Response(text=str(result))

	except ValueError:
		return web.Response(text=f'Invalid IP or ports range')


app = web.Application()
app.add_routes(routes)

if __name__ == '__main__':
	web.run_app(app, host='192.168.1.10', port=8080)
