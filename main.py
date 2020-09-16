#!/usr/bin/env python3

from aiohttp import web
from ipaddress import ip_address

from asyncio import open_connection, wait_for
from asyncio import TimeoutError as ATimeoutError
from asyncio import create_task
from asyncio import Queue


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


async def worker(queue, result):
	'''
	Выполняет задачи из queue по сканированию tcp-портов.

	Результаты сканирования направляет в лист result.
	'''
	while True:
		ip, port = await queue.get()
		result.append(await scan_port(ip, port))
		queue.task_done()


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
		await wait_for(open_connection(ip, port), timeout)
	
	except ATimeoutError:
		return {'port': port, 'state': 'close'}
	
	else:
		return {'port': port, 'state': 'open'}


async def scan_host_ports(ip, ports, scanners_count=1000):
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
	queue = Queue()
	for port in ports:
		queue.put_nowait(tuple([ip, port]))

	result = list()

	workers = [worker(queue, result) for _ in range(scanners_count)]
	tasks = [create_task(worker) for worker in workers]

	await queue.join()
	for task in tasks: task.cancel()

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
