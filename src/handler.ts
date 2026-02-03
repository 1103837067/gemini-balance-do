import { DurableObject } from 'cloudflare:workers';
import { isAdminAuthenticated } from './auth';

class HttpError extends Error {
	status: number;
	constructor(message: string, status: number) {
		super(message);
		this.name = this.constructor.name;
		this.status = status;
	}
}

const fixCors = ({ headers, status, statusText }: { headers?: HeadersInit; status?: number; statusText?: string }) => {
	const newHeaders = new Headers(headers);
	newHeaders.set('Access-Control-Allow-Origin', '*');
	newHeaders.set('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
	newHeaders.set('Access-Control-Allow-Headers', 'Content-Type, Authorization, x-goog-api-key');
	return { headers: newHeaders, status, statusText };
};

const BASE_URL = 'https://generativelanguage.googleapis.com';
const API_VERSION = 'v1beta';
const API_CLIENT = 'genai-js/0.21.0';
const GEMINI_THOUGHT_SIGNATURE_SENTINEL = 'skip_thought_signature_validator';

const makeHeaders = (apiKey: string, more?: Record<string, string>) => ({
	'x-goog-api-client': API_CLIENT,
	...(apiKey && { 'x-goog-api-key': apiKey }),
	...more,
});

/** A Durable Object's behavior is defined in an exported Javascript class */
export class LoadBalancer extends DurableObject {
	env: Env;
	toolThoughtSignatureCache: Map<string, { signature: string; savedAt: number }>;
	/**
	 * The constructor is invoked once upon creation of the Durable Object, i.e. the first call to
	 * 	`DurableObjectStub::get` for a given identifier (no-op constructors can be omitted)
	 *
	 * @param ctx - The interface for interacting with Durable Object state
	 * @param env - The interface to reference bindings declared in wrangler.jsonc
	 */
	constructor(ctx: DurableObjectState, env: Env) {
		super(ctx, env);
		this.env = env;
		this.toolThoughtSignatureCache = new Map();
		// Initialize the database schema upon first creation.
		this.ctx.storage.sql.exec(`
			CREATE TABLE IF NOT EXISTS api_keys (
				api_key TEXT PRIMARY KEY
			);
			CREATE TABLE IF NOT EXISTS api_key_statuses (
				api_key TEXT PRIMARY KEY,
				status TEXT CHECK(status IN ('normal', 'abnormal')) NOT NULL DEFAULT 'normal',
				last_checked_at INTEGER,
				failed_count INTEGER NOT NULL DEFAULT 0,
				key_group TEXT CHECK(key_group IN ('normal', 'abnormal')) NOT NULL DEFAULT 'normal',
				FOREIGN KEY(api_key) REFERENCES api_keys(api_key) ON DELETE CASCADE
			);
		`);
		this.ctx.storage.setAlarm(Date.now() + 5 * 60 * 1000); // Set an alarm to run in 5 minutes
	}

	async alarm() {
		// 1. Handle abnormal keys
		const abnormalKeys = await this.ctx.storage.sql
			.exec("SELECT api_key, failed_count FROM api_key_statuses WHERE key_group = 'abnormal'")
			.raw<any>();

		for (const row of Array.from(abnormalKeys)) {
			const apiKey = row[0] as string;
			const failedCount = row[1] as number;

			try {
				const response = await fetch(`${BASE_URL}/${API_VERSION}/models/gemini-2.5-flash:generateContent?key=${apiKey}`, {
					method: 'POST',
					headers: {
						'Content-Type': 'application/json',
					},
					body: JSON.stringify({
						contents: [{ parts: [{ text: 'hi' }] }],
					}),
				});
				if (response.ok) {
					// Key is working again, move it back to the normal group
					await this.ctx.storage.sql.exec(
						"UPDATE api_key_statuses SET key_group = 'normal', failed_count = 0, last_checked_at = ? WHERE api_key = ?",
						Date.now(),
						apiKey
					);
				} else if (response.status === 429) {
					// Still getting 429, increment failed_count
					const newFailedCount = failedCount + 1;
					if (newFailedCount >= 5) {
						// Delete the key if it has failed 5 times
						await this.ctx.storage.sql.exec('DELETE FROM api_keys WHERE api_key = ?', apiKey);
					} else {
						await this.ctx.storage.sql.exec(
							'UPDATE api_key_statuses SET failed_count = ?, last_checked_at = ? WHERE api_key = ?',
							newFailedCount,
							Date.now(),
							apiKey
						);
					}
				}
			} catch (e) {
				console.error(`Error checking abnormal key ${apiKey}:`, e);
			}
		}

		// 2. Handle normal keys
		const twelveHoursAgo = Date.now() - 12 * 60 * 60 * 1000;
		const normalKeys = await this.ctx.storage.sql
			.exec(
				"SELECT api_key FROM api_key_statuses WHERE key_group = 'normal' AND (last_checked_at IS NULL OR last_checked_at < ?)",
				twelveHoursAgo
			)
			.raw<any>();

		for (const row of Array.from(normalKeys)) {
			const apiKey = row[0] as string;
			try {
				const response = await fetch(`${BASE_URL}/${API_VERSION}/models/gemini-2.5-flash:generateContent?key=${apiKey}`, {
					method: 'POST',
					headers: {
						'Content-Type': 'application/json',
					},
					body: JSON.stringify({
						contents: [{ parts: [{ text: 'hi' }] }],
					}),
				});
				if (response.status === 429) {
					// Move to abnormal group
					await this.ctx.storage.sql.exec(
						"UPDATE api_key_statuses SET key_group = 'abnormal', failed_count = 1, last_checked_at = ? WHERE api_key = ?",
						Date.now(),
						apiKey
					);
				} else {
					// Update last_checked_at
					await this.ctx.storage.sql.exec('UPDATE api_key_statuses SET last_checked_at = ? WHERE api_key = ?', Date.now(), apiKey);
				}
			} catch (e) {
				console.error(`Error checking normal key ${apiKey}:`, e);
			}
		}

		// Reschedule the alarm
		this.ctx.storage.setAlarm(Date.now() + 5 * 60 * 1000);
	}

	async fetch(request: Request): Promise<Response> {
		console.log(`[fetch] Request received: ${request.method} ${request.url}`);
		if (request.method === 'OPTIONS') {
			console.log('[fetch] OPTIONS request, returning 204');
			return new Response(null, {
				status: 204,
				headers: fixCors({}).headers,
			});
		}
		const url = new URL(request.url);
		const pathname = url.pathname;
		console.log(`[fetch] Pathname: ${pathname}`);

		// 静态资源直接放行
		if (pathname === '/favicon.ico' || pathname === '/robots.txt') {
			return new Response('', { status: 204 });
		}

		// 管理 API 权限校验（使用 HOME_ACCESS_KEY）
		if (pathname === '/api/keys' || pathname === '/api/keys/check') {
			if (!isAdminAuthenticated(request, this.env.HOME_ACCESS_KEY)) {
				return new Response(JSON.stringify({ error: 'Unauthorized' }), {
					status: 401,
					headers: fixCors({ headers: { 'Content-Type': 'application/json' } }).headers,
				});
			}
			if (pathname === '/api/keys' && request.method === 'POST') {
				return this.handleApiKeys(request);
			}
			if (pathname === '/api/keys' && request.method === 'GET') {
				return this.getAllApiKeys(request);
			}
			if (pathname === '/api/keys' && request.method === 'DELETE') {
				return this.handleDeleteApiKeys(request);
			}
			if (pathname === '/api/keys/check' && request.method === 'POST') {
				return this.handleApiKeysCheck(request);
			}
		}

		const search = url.search;

		// OpenAI compatible routes
		if (
			pathname.endsWith('/chat/completions') ||
			pathname.endsWith('/completions') ||
			pathname.endsWith('/embeddings') ||
			pathname.endsWith('/v1/models')
		) {
			console.log('[fetch] OpenAI compatible route detected');
			return this.handleOpenAI(request);
		}

		// OpenAI Responses API route
		if (pathname.endsWith('/responses') || pathname.match(/\/responses\/[^/]+$/)) {
			console.log('[fetch] OpenAI Responses API route detected');
			return this.handleResponsesAPI(request);
		}

		// Direct Gemini proxy
		const authKey = this.env.AUTH_KEY;

		let targetUrl = `${BASE_URL}${pathname}${search}`;
		const adjustedRequest = await this.maybeConvertOpenAiRequestForGemini(request, pathname);

		if (this.env.FORWARD_CLIENT_KEY_ENABLED) {
			return this.forwardRequestWithLoadBalancing(targetUrl, adjustedRequest);
		}

		// 传统模式：验证 AUTH_KEY
		if (authKey) {
			let isAuthorized = false;
			// Check key in query parameters
			if (search.includes('key=')) {
				const urlObj = new URL(targetUrl);
				const requestKey = urlObj.searchParams.get('key');
				if (requestKey && requestKey === authKey) {
					isAuthorized = true;
				}
			} else {
				// Check x-goog-api-key in headers
				const requestKey = request.headers.get('x-goog-api-key');
				if (requestKey && requestKey === authKey) {
					isAuthorized = true;
				}
			}

			if (!isAuthorized) {
				return new Response('Unauthorized', { status: 401, headers: fixCors({}).headers });
			}
		}
		// If authKey is not set, or if it was authorized, proceed to forward with load balancing.
		return this.forwardRequestWithLoadBalancing(targetUrl, adjustedRequest);
	}

	async forwardRequest(targetUrl: string, request: Request, headers: Headers, apiKey: string): Promise<Response> {
		console.log(`Request Sending to Gemini: ${targetUrl}`);

		const response = await fetch(targetUrl, {
			method: request.method,
			headers: headers,
			body: request.method === 'GET' || request.method === 'HEAD' ? null : request.body,
		});

		if (response.status === 429) {
			console.log(`API key ${apiKey} received 429 status code.`);
			await this.ctx.storage.sql.exec(
				"UPDATE api_key_statuses SET key_group = 'abnormal', failed_count = failed_count + 1, last_checked_at = ? WHERE api_key = ?",
				Date.now(),
				apiKey
			);
		}

		console.log('Call Gemini Success');

		const responseHeaders = new Headers(response.headers);
		responseHeaders.set('Access-Control-Allow-Origin', '*');
		responseHeaders.delete('transfer-encoding');
		responseHeaders.delete('connection');
		responseHeaders.delete('keep-alive');
		responseHeaders.delete('content-encoding');
		responseHeaders.set('Referrer-Policy', 'no-referrer');

		return new Response(response.body, {
			status: response.status,
			headers: responseHeaders,
		});
	}

	// 对请求进行负载均衡，随机分发key
	private async forwardRequestWithLoadBalancing(targetUrl: string, request: Request): Promise<Response> {
		try {
			let headers = new Headers();
			const url = new URL(targetUrl);

			// Forward content-type header
			if (request.headers.has('content-type')) {
				headers.set('content-type', request.headers.get('content-type')!);
			}

			if (this.env.FORWARD_CLIENT_KEY_ENABLED) {
				// 提取客户端的 API key
				const clientApiKey = this.extractClientApiKey(request, url);

				if (clientApiKey) {
					url.searchParams.set('key', clientApiKey);
					headers.set('x-goog-api-key', clientApiKey);
				}

				return this.forwardRequest(url.toString(), request, headers, clientApiKey || '');
			}
			const apiKey = await this.getRandomApiKey();
			if (!apiKey) {
				return new Response('No API keys configured in the load balancer.', { status: 500 });
			}

			url.searchParams.set('key', apiKey);
			headers.set('x-goog-api-key', apiKey);
			return this.forwardRequest(url.toString(), request, headers, apiKey);
		} catch (error) {
			console.error('Failed to fetch:', error);
			return new Response('Internal Server Error\n' + error, {
				status: 500,
				headers: { 'Content-Type': 'text/plain' },
			});
		}
	}

	async handleModels(apiKey: string) {
		const response = await fetch(`${BASE_URL}/${API_VERSION}/models`, {
			headers: makeHeaders(apiKey),
		});

		let responseBody: BodyInit | null = response.body;
		if (response.ok) {
			const { models } = JSON.parse(await response.text());
			responseBody = JSON.stringify(
				{
					object: 'list',
					data: models.map(({ name }: any) => ({
						id: name.replace('models/', ''),
						object: 'model',
						created: 0,
						owned_by: '',
					})),
				},
				null,
				'  '
			);
		}
		return new Response(responseBody, fixCors(response));
	}

	async handleEmbeddings(req: any, apiKey: string) {
		const DEFAULT_EMBEDDINGS_MODEL = 'text-embedding-004';

		if (typeof req.model !== 'string') {
			throw new HttpError('model is not specified', 400);
		}

		let model;
		if (req.model.startsWith('models/')) {
			model = req.model;
		} else {
			if (!req.model.startsWith('gemini-')) {
				req.model = DEFAULT_EMBEDDINGS_MODEL;
			}
			model = 'models/' + req.model;
		}

		if (!Array.isArray(req.input)) {
			req.input = [req.input];
		}

		const response = await fetch(`${BASE_URL}/${API_VERSION}/${model}:batchEmbedContents`, {
			method: 'POST',
			headers: makeHeaders(apiKey, { 'Content-Type': 'application/json' }),
			body: JSON.stringify({
				requests: req.input.map((text: string) => ({
					model,
					content: { parts: { text } },
					outputDimensionality: req.dimensions,
				})),
			}),
		});

		let responseBody: BodyInit | null = response.body;
		if (response.ok) {
			const { embeddings } = JSON.parse(await response.text());
			responseBody = JSON.stringify(
				{
					object: 'list',
					data: embeddings.map(({ values }: any, index: number) => ({
						object: 'embedding',
						index,
						embedding: values,
					})),
					model: req.model,
				},
				null,
				'  '
			);
		}
		return new Response(responseBody, fixCors(response));
	}

	async handleCompletions(req: any, apiKey: string) {
		const DEFAULT_MODEL = 'gemini-2.5-flash';
		let model = DEFAULT_MODEL;

		switch (true) {
			case typeof req.model !== 'string':
				break;
			case req.model.startsWith('models/'):
				model = req.model.substring(7);
				break;
			case req.model.startsWith('gemini-'):
			case req.model.startsWith('gemma-'):
			case req.model.startsWith('learnlm-'):
				model = req.model;
		}

		let body = await this.transformRequest(req);
		const extra = req.extra_body?.google;

		if (extra) {
			if (extra.safety_settings) {
				body.safetySettings = extra.safety_settings;
			}
			if (extra.cached_content) {
				body.cachedContent = extra.cached_content;
			}
			if (extra.thinking_config) {
				body.generationConfig.thinkingConfig = extra.thinking_config;
			}
		}

		switch (true) {
			case model.endsWith(':search'):
				model = model.substring(0, model.length - 7);
			case req.model.endsWith('-search-preview'):
			case req.tools?.some((tool: any) => tool.function?.name === 'googleSearch'):
				body.tools = body.tools || [];
				body.tools.push({ function_declarations: [{ name: 'googleSearch', parameters: {} }] });
		}

		const TASK = req.stream ? 'streamGenerateContent' : 'generateContent';
		let url = `${BASE_URL}/${API_VERSION}/models/${model}:${TASK}`;
		if (req.stream) {
			url += '?alt=sse';
		}

		const response = await fetch(url, {
			method: 'POST',
			headers: makeHeaders(apiKey, { 'Content-Type': 'application/json' }),
			body: JSON.stringify(body),
		});

		let responseBody: BodyInit | null = response.body;
		if (response.ok) {
			let id = 'chatcmpl-' + this.generateId();
			const shared = {};

			if (req.stream) {
				responseBody = response
					.body!.pipeThrough(new TextDecoderStream())
					.pipeThrough(
						new TransformStream({
							transform: this.parseStream,
							flush: this.parseStreamFlush,
							buffer: '',
							shared,
						} as any)
					)
					.pipeThrough(
						new TransformStream({
							transform: this.toOpenAiStream,
							flush: this.toOpenAiStreamFlush,
							streamIncludeUsage: req.stream_options?.include_usage,
							model,
							id,
							last: [],
							reasoningLast: [],
							toolCallIds: {},
							toolCallArgs: {},
							extractThoughtSignatureFromCandidate: this.extractThoughtSignatureFromCandidate.bind(this),
							extractThoughtSignatureFromPart: this.extractThoughtSignatureFromPart.bind(this),
							extractThoughtSignature: this.extractThoughtSignature.bind(this),
							cacheToolThoughtSignature: this.cacheToolThoughtSignature.bind(this),
							shared,
						} as any)
					)
					.pipeThrough(new TextEncoderStream());
			} else {
				let body: any = await response.text();
				try {
					body = JSON.parse(body);
					if (!body.candidates) {
						throw new Error('Invalid completion object');
					}
				} catch (err) {
					console.error('Error parsing response:', err);
					return new Response(JSON.stringify({ error: 'Failed to parse response' }), {
						...fixCors(response),
						status: 500,
					});
				}
				responseBody = this.processCompletionsResponse(body, model, id);
			}
		}
		return new Response(responseBody, fixCors(response));
	}

	// 辅助方法
	private generateId(): string {
		const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
		const randomChar = () => characters[Math.floor(Math.random() * characters.length)];
		return Array.from({ length: 29 }, randomChar).join('');
	}

	private async transformRequest(req: any) {
		const harmCategory = [
			'HARM_CATEGORY_HATE_SPEECH',
			'HARM_CATEGORY_SEXUALLY_EXPLICIT',
			'HARM_CATEGORY_DANGEROUS_CONTENT',
			'HARM_CATEGORY_HARASSMENT',
			'HARM_CATEGORY_CIVIC_INTEGRITY',
		];

		const safetySettings = harmCategory.map((category) => ({
			category,
			threshold: 'BLOCK_NONE',
		}));

		return {
			...(await this.transformMessages(req.messages)),
			safetySettings,
			generationConfig: this.transformConfig(req),
			...this.transformTools(req),
			cachedContent: undefined as any,
		};
	}

	private transformConfig(req: any) {
		const fieldsMap: Record<string, string> = {
			frequency_penalty: 'frequencyPenalty',
			max_completion_tokens: 'maxOutputTokens',
			max_tokens: 'maxOutputTokens',
			n: 'candidateCount',
			presence_penalty: 'presencePenalty',
			seed: 'seed',
			stop: 'stopSequences',
			temperature: 'temperature',
			top_k: 'topK',
			top_p: 'topP',
		};

		const thinkingBudgetMap: Record<string, number> = {
			low: 1024,
			medium: 8192,
			high: 24576,
		};

		let cfg: any = {};
		for (let key in req) {
			const matchedKey = fieldsMap[key];
			if (matchedKey) {
				cfg[matchedKey] = req[key];
			}
		}

		if (req.response_format) {
			switch (req.response_format.type) {
				case 'json_schema':
					cfg.responseSchema = req.response_format.json_schema?.schema;
					if (cfg.responseSchema && 'enum' in cfg.responseSchema) {
						cfg.responseMimeType = 'text/x.enum';
						break;
					}
				case 'json_object':
					cfg.responseMimeType = 'application/json';
					break;
				case 'text':
					cfg.responseMimeType = 'text/plain';
					break;
				default:
					throw new HttpError('Unsupported response_format.type', 400);
			}
		}
		if (req.reasoning_effort) {
			cfg.thinkingConfig = { thinkingBudget: thinkingBudgetMap[req.reasoning_effort] };
		}

		return cfg;
	}

	private async transformMessages(messages: any[]) {
		if (!messages) {
			return {};
		}

		const contents: any[] = [];
		let system_instruction;

		for (const item of messages) {
			switch (item.role) {
				case 'system':
					system_instruction = { parts: await this.transformMsg(item) };
					continue;
			case 'assistant':
				item.role = 'model';
				break;
				case 'user':
					break;
			case 'tool':
				// 工具响应消息：转换为 Gemini 的 functionResponse 格式
				// OpenAI 格式: { role: "tool", tool_call_id: "call_abc", content: "result" }
				// Gemini 格式: { role: "user", parts: [{ functionResponse: { name: "xxx", response: "result" } }] }
				if (item.tool_call_id) {
					// 从 tool_call_id 中提取工具名称
					// format: "call_{tool_name}_{timestamp}"
					const toolNameMatch = item.tool_call_id.match(/^call_([^_]+)_/);
					const toolName = item.name || (toolNameMatch ? toolNameMatch[1] : 'unknown');

						// 将 content 解析为对象（Gemini 要求 response 是对象，不是字符串）
						let responseData = item.content;
						if (typeof item.content === 'string') {
							try {
								responseData = JSON.parse(item.content);
							} catch {
								// 如果解析失败，保持原值
								responseData = item.content;
							}
						}

					const responsePayload =
						responseData && typeof responseData === 'object' && 'output' in responseData
							? responseData
							: { output: responseData };
					// 添加 functionResponse part
					contents.push({
						role: 'user',
						parts: [{
							functionResponse: {
								id: item.tool_call_id,
								name: toolName,
								response: responsePayload,
							},
						}],
					});
				}
				continue;
				default:
					throw new HttpError(`Unknown message role: "${item.role}"`, 400);
			}

			if (system_instruction) {
				// 修复：确保 parts 是数组后再调用 some 方法
				if (!contents[0]?.parts || (Array.isArray(contents[0]?.parts) && !contents[0]?.parts.some((part: any) => part.text))) {
					contents.unshift({ role: 'user', parts: [{ text: ' ' }] });
				}
			}

			if (item.role === 'model' && Array.isArray(item.tool_calls) && item.tool_calls.length > 0) {
				const parts = await this.transformMsg(item);
				for (const toolCall of item.tool_calls) {
					const toolCallId = toolCall.id;
					// 优先使用缓存的签名，否则使用 sentinel 值
					// 注意：始终添加 thoughtSignature 以确保工具调用正常工作
					const signature = this.getCachedToolThoughtSignature(toolCallId) || GEMINI_THOUGHT_SIGNATURE_SENTINEL;
					let args = toolCall.function?.arguments ?? {};
					if (typeof args === 'string') {
						try {
							args = JSON.parse(args);
						} catch {
							args = {};
						}
					}
					parts.push({
						thoughtSignature: signature,
						functionCall: {
							id: toolCallId,
							name: toolCall.function?.name || 'unknown',
							args,
						},
					});
				}
				contents.push({
					role: item.role,
					parts,
				});
				continue;
			}
			contents.push({
				role: item.role,
				parts: await this.transformMsg(item),
			});
		}

		return { system_instruction, contents };
	}

	private async transformMsg({ content }: any) {
		const parts: any[] = [];
		if (!Array.isArray(content)) {
			parts.push({ text: content });
			return parts;
		}

		for (const item of content) {
			switch (item.type) {
				case 'text':
					parts.push({ text: item.text });
					break;
				case 'image_url':
					parts.push(await this.parseImg(item.image_url.url));
					break;
				case 'input_audio':
					parts.push({
						inlineData: {
							mimeType: 'audio/' + item.input_audio.format,
							data: item.input_audio.data,
						},
					});
					break;
				default:
					throw new HttpError(`Unknown "content" item type: "${item.type}"`, 400);
			}
		}

		if (content.every((item) => item.type === 'image_url')) {
			parts.push({ text: '' }); // to avoid "Unable to submit request because it must have a text parameter"
		}
		return parts;
	}
	private async parseImg(url: any) {
		let mimeType, data;
		if (url.startsWith('http://') || url.startsWith('https://')) {
			try {
				const response = await fetch(url);
				if (!response.ok) {
					throw new Error(`${response.status} ${response.statusText} (${url})`);
				}
				mimeType = response.headers.get('content-type');
				data = Buffer.from(await response.arrayBuffer()).toString('base64');
			} catch (err) {
				throw new Error('Error fetching image: ' + (err as Error).message);
			}
		} else {
			const match = url.match(/^data:(?<mimeType>.*?)(;base64)?,(?<data>.*)$/);
			if (!match) {
				throw new HttpError('Invalid image data: ' + url, 400);
			}
			({ mimeType, data } = match.groups);
		}
		return {
			inlineData: {
				mimeType,
				data,
			},
		};
	}

	private adjustSchema(schema: any) {
		// schema 格式: { type: 'function', function: { name, parameters, strict } }
		// 我们需要处理 function.parameters 中的 schema，并删除不兼容的字段
		const funcDef = schema.function;
		if (funcDef) {
			// 删除 strict 字段（Gemini API 不支持）
			delete funcDef.strict;
			if (funcDef.parameters && typeof funcDef.parameters === 'object') {
				this.adjustProps(funcDef.parameters);
			}
		}
	}

	private adjustProps(schemaPart: any) {
		if (typeof schemaPart !== 'object' || schemaPart === null) {
			return;
		}
		if (Array.isArray(schemaPart)) {
			schemaPart.forEach((item) => this.adjustProps(item));
		} else {
			// 删除 $schema 字段（Gemini API 不支持）
			delete schemaPart.$schema;
			// 删除 additionalProperties: false（Gemini API 不支持）
			if (schemaPart.type === 'object' && schemaPart.properties && schemaPart.additionalProperties === false) {
				delete schemaPart.additionalProperties;
			}
			Object.values(schemaPart).forEach((value) => this.adjustProps(value));
		}
	}

	private async maybeConvertOpenAiRequestForGemini(request: Request, pathname: string): Promise<Request> {
		if (!pathname.startsWith(`/${API_VERSION}/models/`)) {
			return request;
		}
		if (request.method !== 'POST') {
			return request;
		}
		const contentType = request.headers.get('content-type') || '';
		if (!contentType.includes('application/json')) {
			return request;
		}

		let rawBody: any;
		try {
			rawBody = await request.clone().json();
		} catch {
			return request;
		}

		const looksLikeOpenAi =
			Array.isArray(rawBody?.messages) ||
			rawBody?.tools ||
			rawBody?.tool_choice ||
			rawBody?.stream !== undefined ||
			rawBody?.max_tokens !== undefined;
		if (!looksLikeOpenAi) {
			return request;
		}

		const convertedBody = await this.transformRequest(rawBody);
		const headers = new Headers(request.headers);
		headers.set('content-type', 'application/json');
		return new Request(request.url, {
			method: request.method,
			headers,
			body: JSON.stringify(convertedBody),
		});
	}

	private extractThoughtSignature(value: any): string | null {
		if (!value || typeof value !== 'object') {
			return null;
		}
		const signature = value.thoughtSignature || value.thought_signature || value.signature;
		if (!signature || typeof signature !== 'string') {
			return null;
		}
		return signature;
	}

	private extractThoughtSignatureFromPart(part: any): string | null {
		if (!part || typeof part !== 'object') {
			return null;
		}
		return (
			this.extractThoughtSignature(part) ||
			this.extractThoughtSignature(part.metadata) ||
			this.extractThoughtSignature(part.functionCall) ||
			this.extractThoughtSignature(part.function_call) ||
			this.extractThoughtSignature(part.functionCall?.metadata) ||
			this.extractThoughtSignature(part.functionResponse) ||
			this.extractThoughtSignature(part.function_response) ||
			this.extractThoughtSignature(part.functionResponse?.metadata) ||
			null
		);
	}

	private extractThoughtSignatureFromCandidate(candidate: any, data?: any): string | null {
		return (
			this.extractThoughtSignature(candidate) ||
			this.extractThoughtSignature(candidate?.content) ||
			this.extractThoughtSignature(data) ||
			null
		);
	}

	private cacheToolThoughtSignature(id: string | null | undefined, signature: string | null | undefined) {
		if (!id || !signature) {
			return;
		}
		this.toolThoughtSignatureCache.set(id, { signature, savedAt: Date.now() });
	}

	private getCachedToolThoughtSignature(id: string | null | undefined): string | null {
		if (!id) {
			return null;
		}
		const cached = this.toolThoughtSignatureCache.get(id);
		if (!cached) {
			return null;
		}
		if (Date.now() - cached.savedAt > 6 * 60 * 60 * 1000) {
			this.toolThoughtSignatureCache.delete(id);
			return null;
		}
		return cached.signature;
	}

	private transformTools(req: any) {
		let tools, tool_config;
		if (req.tools) {
			console.log('[transformTools] Input tools:', JSON.stringify(req.tools, null, 2));
			const funcs = req.tools.filter((tool: any) => tool.type === 'function' && tool.function?.name !== 'googleSearch');
			if (funcs.length > 0) {
				// 修复 this 绑定问题
				funcs.forEach((schema: any) => this.adjustSchema(schema));
				tools = [{ function_declarations: funcs.map((schema: any) => schema.function) }];
				console.log('[transformTools] Output tools:', JSON.stringify(tools, null, 2));
			}
		}
		if (req.tool_choice) {
			const allowed_function_names = req.tool_choice?.type === 'function' ? [req.tool_choice?.function?.name] : undefined;
			if (allowed_function_names || typeof req.tool_choice === 'string') {
				tool_config = {
					function_calling_config: {
						mode: allowed_function_names ? 'ANY' : req.tool_choice.toUpperCase(),
						allowed_function_names,
					},
				};
			}
		}
		return { tools, tool_config };
	}

	private processCompletionsResponse(data: any, model: string, id: string) {
		const reasonsMap: Record<string, string> = {
			STOP: 'stop',
			MAX_TOKENS: 'length',
			SAFETY: 'content_filter',
			RECITATION: 'content_filter',
		};

		const transformCandidatesMessage = (cand: any) => {
			const message = { role: 'assistant', content: [] as string[] };
			let reasoningContent = '';
			let finalContent = '';
			let toolCalls: any[] = [];

			const candidateSignature = this.extractThoughtSignatureFromCandidate(cand, data);
			for (const part of cand.content?.parts ?? []) {
				// 处理工具调用
				if (part.functionCall) {
					const toolCallId = `call_${part.functionCall.name}_${Date.now()}`;
					const signature = this.extractThoughtSignatureFromPart(part) || candidateSignature;
					this.cacheToolThoughtSignature(toolCallId, signature);
					toolCalls.push({
						id: toolCallId,
						type: 'function',
						function: {
							name: part.functionCall.name,
							arguments: JSON.stringify(part.functionCall.args || {}),
						},
					});
				}
				// 处理文本内容
				else if (part.text) {
					// 检查是否是思考内容
					// Gemini API 可能使用多种方式标识思考内容
					const isThoughtContent =
						part.thoughtToken ||
						part.thought ||
						part.thoughtTokens ||
						(part.executableCode && part.executableCode.language === 'thought') ||
						// 检查文本是否以思考标记开头
						(part.text && (part.text.startsWith('<thinking>') || part.text.startsWith('思考：') || part.text.startsWith('Thinking:')));

					if (isThoughtContent) {
						// 这是思考内容，应该放在 reasoning_content 字段中
						// 如果文本包含思考标记，需要移除这些标记
						let cleanText = part.text;
						if (cleanText.startsWith('<thinking>')) {
							cleanText = cleanText.replace('<thinking>', '').replace('</thinking>', '');
						} else if (cleanText.startsWith('思考：')) {
							cleanText = cleanText.replace('思考：', '');
						} else if (cleanText.startsWith('Thinking:')) {
							cleanText = cleanText.replace('Thinking:', '');
						}
						reasoningContent += cleanText;
					} else {
						// 这是正常的回答内容
						finalContent += part.text;
					}
				}
			}

			const messageObj: any = {
				index: cand.index || 0,
				message: {
					role: 'assistant',
					content: finalContent || null,
				},
				logprobs: null,
				finish_reason: toolCalls.length > 0 ? 'tool_calls' : reasonsMap[cand.finishReason] || cand.finishReason,
			};

			// 如果有思考内容，添加到响应中
			if (reasoningContent) {
				messageObj.message.reasoning_content = reasoningContent;
			}

			// 如果有工具调用，添加到响应中
			if (toolCalls.length > 0) {
				messageObj.message.tool_calls = toolCalls;
			}

			return messageObj;
		};

		const obj = {
			id,
			choices: data.candidates.map(transformCandidatesMessage),
			created: Math.floor(Date.now() / 1000),
			model: data.modelVersion ?? model,
			object: 'chat.completion',
			usage: data.usageMetadata && {
				completion_tokens: data.usageMetadata.candidatesTokenCount,
				prompt_tokens: data.usageMetadata.promptTokenCount,
				total_tokens: data.usageMetadata.totalTokenCount,
			},
		};

		return JSON.stringify(obj);
	}

	// 流处理方法
	private parseStream(this: any, chunk: string, controller: any) {
		this.buffer += chunk;
		const lines = this.buffer.split('\n');
		this.buffer = lines.pop()!;

		for (const line of lines) {
			if (line.startsWith('data: ')) {
				const data = line.substring(6);
				if (data.startsWith('{')) {
					controller.enqueue(JSON.parse(data));
				}
			}
		}
	}

	private parseStreamFlush(this: any, controller: any) {
		if (this.buffer) {
			try {
				controller.enqueue(JSON.parse(this.buffer));
				this.shared.is_buffers_rest = true;
			} catch (e) {
				console.error('Error parsing remaining buffer:', e);
			}
		}
	}

	private toOpenAiStream(this: any, line: any, controller: any) {
		const reasonsMap: Record<string, string> = {
			STOP: 'stop',
			MAX_TOKENS: 'length',
			SAFETY: 'content_filter',
			RECITATION: 'content_filter',
		};

		const { candidates, usageMetadata } = line;
		if (usageMetadata) {
			this.shared.usage = {
				completion_tokens: usageMetadata.candidatesTokenCount,
				prompt_tokens: usageMetadata.promptTokenCount,
				total_tokens: usageMetadata.totalTokenCount,
			};
		}

		if (candidates) {
			for (const cand of candidates) {
				const { index, content, finishReason } = cand;
				const { parts } = content;
				const candidateSignature = this.extractThoughtSignatureFromCandidate(cand, line);

				// 分别处理思考内容、正常内容和工具调用
				let reasoningText = '';
				let finalText = '';
				let functionCalls: Array<{ call: any; signature: string | null }> = [];

				for (const part of parts) {
					// 处理工具调用
					if (part.functionCall) {
						functionCalls.push({
							call: part.functionCall,
							signature: this.extractThoughtSignatureFromPart(part) || candidateSignature,
						});
					}
					// 处理文本内容
					else if (part.text) {
						// 检查是否是思考内容
						// Gemini API 可能使用多种方式标识思考内容
						const isThoughtContent =
							part.thoughtToken ||
							part.thought ||
							part.thoughtTokens ||
							(part.executableCode && part.executableCode.language === 'thought') ||
							// 检查文本是否以思考标记开头
							(part.text && (part.text.startsWith('<thinking>') || part.text.startsWith('思考：') || part.text.startsWith('Thinking:')));

						if (isThoughtContent) {
							// 这是思考内容
							// 如果文本包含思考标记，需要移除这些标记
							let cleanText = part.text;
							if (cleanText.startsWith('<thinking>')) {
								cleanText = cleanText.replace('<thinking>', '').replace('</thinking>', '');
							} else if (cleanText.startsWith('思考：')) {
								cleanText = cleanText.replace('思考：', '');
							} else if (cleanText.startsWith('Thinking:')) {
								cleanText = cleanText.replace('Thinking:', '');
							}
							reasoningText += cleanText;
						} else {
							// 这是正常的回答内容
							finalText += part.text;
						}
					}
				}

				// 处理工具调用的流式输出
				if (functionCalls.length > 0) {
				for (const [toolCallIndex, fc] of functionCalls.entries()) {
					const toolCallKey = `${index}_${toolCallIndex}`;

					// 生成或获取 tool_call_id
					if (!this.toolCallIds[toolCallKey]) {
						this.toolCallIds[toolCallKey] = `call_${fc.call.name}_${Date.now()}`;
					}
					const toolCallId = this.toolCallIds[toolCallKey];
					this.cacheToolThoughtSignature(toolCallId, fc.signature);

						// 将 args 转换为 JSON 字符串
					const argsStr = JSON.stringify(fc.call.args || {});

						// 获取上次发送的参数长度
						const lastArgsLength = this.toolCallArgs[toolCallKey] || 0;

						// 计算增量
						if (argsStr.length > lastArgsLength) {
							const argsDelta = argsStr.substring(lastArgsLength);

							// 创建 delta 对象
							const deltaObj: any = {
								tool_calls: [
									{
										index: toolCallIndex,
										id: toolCallId,
									},
								],
							};

							// 如果是首次发送，添加 type 和 name
							if (lastArgsLength === 0) {
								deltaObj.tool_calls[0].type = 'function';
								deltaObj.tool_calls[0].function = {
									name: fc.call.name,
								};
							}

							// 如果有增量参数，添加 arguments
							if (argsDelta) {
								if (!deltaObj.tool_calls[0].function) {
									deltaObj.tool_calls[0].function = {};
								}
								deltaObj.tool_calls[0].function.arguments = argsDelta;
							}

							// 只在有内容时才发送
							if (lastArgsLength === 0 || argsDelta) {
								const toolCallObj = {
									id: this.id,
									object: 'chat.completion.chunk',
									created: Math.floor(Date.now() / 1000),
									model: this.model,
									choices: [
										{
											index,
											delta: deltaObj,
											finish_reason: null,
										},
									],
								};
								controller.enqueue(`data: ${JSON.stringify(toolCallObj)}\n\n`);
							}

							// 更新已发送的参数长度
							this.toolCallArgs[toolCallKey] = argsStr.length;
						}
						if (!this.toolCallsSeen) {
							this.toolCallsSeen = {};
						}
						this.toolCallsSeen[index] = true;
					}
				}

				// 处理思考内容的流式输出
				if (reasoningText) {
					if (!this.reasoningLast) this.reasoningLast = {};
					if (this.reasoningLast[index] === undefined) {
						this.reasoningLast[index] = '';
					}

					const lastReasoningText = this.reasoningLast[index] || '';
					let reasoningDelta = '';

					if (reasoningText.startsWith(lastReasoningText)) {
						reasoningDelta = reasoningText.substring(lastReasoningText.length);
					} else {
						// Find the common prefix
						let i = 0;
						while (i < reasoningText.length && i < lastReasoningText.length && reasoningText[i] === lastReasoningText[i]) {
							i++;
						}
						reasoningDelta = reasoningText.substring(i);
					}

					this.reasoningLast[index] = reasoningText;

					if (reasoningDelta) {
						const reasoningObj = {
							id: this.id,
							object: 'chat.completion.chunk',
							created: Math.floor(Date.now() / 1000),
							model: this.model,
							choices: [
								{
									index,
									delta: { reasoning_content: reasoningDelta },
									finish_reason: null,
								},
							],
						};
						controller.enqueue(`data: ${JSON.stringify(reasoningObj)}\n\n`);
					}
				}

				// 处理正常内容的流式输出
				if (finalText) {
					if (this.last[index] === undefined) {
						this.last[index] = '';
					}

					const lastText = this.last[index] || '';
					let delta = '';

					if (finalText.startsWith(lastText)) {
						delta = finalText.substring(lastText.length);
					} else {
						// Find the common prefix
						let i = 0;
						while (i < finalText.length && i < lastText.length && finalText[i] === lastText[i]) {
							i++;
						}
						// Send the rest of the new text as delta.
						// This might not be perfect for all clients, but it prevents data loss.
						delta = finalText.substring(i);
					}

					this.last[index] = finalText;

					if (delta) {
						const obj = {
							id: this.id,
							object: 'chat.completion.chunk',
							created: Math.floor(Date.now() / 1000),
							model: this.model,
							choices: [
								{
									index,
									delta: { content: delta },
									finish_reason: null,
								},
							],
						};
						controller.enqueue(`data: ${JSON.stringify(obj)}\n\n`);
					}
				}

				// 如果有完成原因，发送完成信号
				if (finishReason) {
					const finishObj = {
						id: this.id,
						object: 'chat.completion.chunk',
						created: Math.floor(Date.now() / 1000),
						model: this.model,
						choices: [
							{
								index,
								delta: {},
								finish_reason: this.toolCallsSeen?.[index] ? 'tool_calls' : reasonsMap[finishReason] || finishReason,
							},
						],
					};
					controller.enqueue(`data: ${JSON.stringify(finishObj)}\n\n`);
				}
			}
		}
	}

	private toOpenAiStreamFlush(this: any, controller: any) {
		if (this.streamIncludeUsage && this.shared.usage) {
			const obj = {
				id: this.id,
				object: 'chat.completion.chunk',
				created: Math.floor(Date.now() / 1000),
				model: this.model,
				choices: [
					{
						index: 0,
						delta: {},
						finish_reason: 'stop',
					},
				],
				usage: this.shared.usage,
			};
			controller.enqueue(`data: ${JSON.stringify(obj)}\n\n`);
		}
		controller.enqueue('data: [DONE]\n\n');
	}
	// =================================================================================================
	// Admin API Handlers
	// =================================================================================================

	async handleApiKeys(request: Request): Promise<Response> {
		try {
			const { keys } = (await request.json()) as { keys: string[] };
			if (!Array.isArray(keys) || keys.length === 0) {
				return new Response(JSON.stringify({ error: '请求体无效，需要一个包含key的非空数组。' }), {
					status: 400,
					headers: { 'Content-Type': 'application/json' },
				});
			}

			for (const key of keys) {
				await this.ctx.storage.sql.exec('INSERT OR IGNORE INTO api_keys (api_key) VALUES (?)', key);
				await this.ctx.storage.sql.exec('INSERT OR IGNORE INTO api_key_statuses (api_key) VALUES (?)', key);
			}

			return new Response(JSON.stringify({ message: 'API密钥添加成功。' }), {
				status: 200,
				headers: { 'Content-Type': 'application/json' },
			});
		} catch (error: any) {
			console.error('处理API密钥失败:', error);
			return new Response(JSON.stringify({ error: error.message || '内部服务器错误' }), {
				status: 500,
				headers: { 'Content-Type': 'application/json' },
			});
		}
	}

	async handleDeleteApiKeys(request: Request): Promise<Response> {
		try {
			const { keys } = (await request.json()) as { keys: string[] };
			if (!Array.isArray(keys) || keys.length === 0) {
				return new Response(JSON.stringify({ error: '请求体无效，需要一个包含key的非空数组。' }), {
					status: 400,
					headers: { 'Content-Type': 'application/json' },
				});
			}

			const batchSize = 500;
			for (let i = 0; i < keys.length; i += batchSize) {
				const batch = keys.slice(i, i + batchSize);
				const placeholders = batch.map(() => '?').join(',');
				await this.ctx.storage.sql.exec(`DELETE FROM api_keys WHERE api_key IN (${placeholders})`, ...batch);
			}

			return new Response(JSON.stringify({ message: 'API密钥删除成功。' }), {
				status: 200,
				headers: { 'Content-Type': 'application/json' },
			});
		} catch (error: any) {
			console.error('删除API密钥失败:', error);
			return new Response(JSON.stringify({ error: error.message || '内部服务器错误' }), {
				status: 500,
				headers: { 'Content-Type': 'application/json' },
			});
		}
	}

	async handleApiKeysCheck(request: Request): Promise<Response> {
		try {
			const { keys } = (await request.json()) as { keys: string[] };
			if (!Array.isArray(keys) || keys.length === 0) {
				return new Response(JSON.stringify({ error: '请求体无效，需要一个包含key的非空数组。' }), {
					status: 400,
					headers: { 'Content-Type': 'application/json' },
				});
			}

			const checkResults = await Promise.all(
				keys.map(async (key) => {
					try {
						const response = await fetch(`${BASE_URL}/${API_VERSION}/models/gemini-2.5-flash:generateContent?key=${key}`, {
							method: 'POST',
							headers: {
								'Content-Type': 'application/json',
							},
							body: JSON.stringify({
								contents: [{ parts: [{ text: 'hi' }] }],
							}),
						});
						return { key, valid: response.ok, error: response.ok ? null : await response.text() };
					} catch (e: any) {
						return { key, valid: false, error: e.message };
					}
				})
			);

			for (const result of checkResults) {
				if (result.valid) {
					await this.ctx.storage.sql.exec(
						"UPDATE api_key_statuses SET status = 'normal', key_group = 'normal', failed_count = 0, last_checked_at = ? WHERE api_key = ?",
						Date.now(),
						result.key
					);
				} else {
					await this.ctx.storage.sql.exec('DELETE FROM api_keys WHERE api_key = ?', result.key);
				}
			}

			return new Response(JSON.stringify(checkResults), {
				headers: { 'Content-Type': 'application/json' },
			});
		} catch (error: any) {
			console.error('检查API密钥失败:', error);
			return new Response(JSON.stringify({ error: error.message || '内部服务器错误' }), {
				status: 500,
				headers: { 'Content-Type': 'application/json' },
			});
		}
	}

	async getAllApiKeys(request: Request): Promise<Response> {
		try {
			const url = new URL(request.url);
			const page = parseInt(url.searchParams.get('page') || '1', 10);
			const pageSize = parseInt(url.searchParams.get('pageSize') || '50', 10);
			const offset = (page - 1) * pageSize;

			const totalResult = await this.ctx.storage.sql.exec('SELECT COUNT(*) as count FROM api_key_statuses').raw<any>();
			const totalArray = Array.from(totalResult);
			const total = totalArray.length > 0 ? totalArray[0][0] : 0;

			const results = await this.ctx.storage.sql
				.exec('SELECT api_key, status, key_group, last_checked_at, failed_count FROM api_key_statuses LIMIT ? OFFSET ?', pageSize, offset)
				.raw<any>();
			const keys = results
				? Array.from(results).map((row: any) => ({
						api_key: row[0],
						status: row[1],
						key_group: row[2],
						last_checked_at: row[3],
						failed_count: row[4],
				  }))
				: [];

			return new Response(JSON.stringify({ keys, total }), {
				headers: { 'Content-Type': 'application/json' },
			});
		} catch (error: any) {
			console.error('获取API密钥失败:', error);
			return new Response(JSON.stringify({ error: error.message || '内部服务器错误' }), {
				status: 500,
				headers: { 'Content-Type': 'application/json' },
			});
		}
	}

	// =================================================================================================
	// Helper Methods
	// =================================================================================================

	/**
	 * 从请求中提取客户端的 API key
	 * 支持多种传递方式：查询参数、x-goog-api-key header、Authorization header
	 */
	private extractClientApiKey(request: Request, url: URL): string | null {
		// 从查询参数中提取
		if (url.searchParams.has('key')) {
			const key = url.searchParams.get('key');
			if (key) return key;
		}

		// 从 x-goog-api-key header 中提取
		const googApiKey = request.headers.get('x-goog-api-key');
		if (googApiKey) return googApiKey;

		// 从 Authorization header 中提取 (Bearer token)
		const authHeader = request.headers.get('Authorization');
		if (authHeader && authHeader.startsWith('Bearer ')) {
			return authHeader.substring(7);
		}

		return null;
	}

	private async getRandomApiKey(): Promise<string | null> {
		try {
			// First, try to get a key from the normal group
			let results = await this.ctx.storage.sql
				.exec("SELECT api_key FROM api_key_statuses WHERE key_group = 'normal' ORDER BY RANDOM() LIMIT 1")
				.raw<any>();
			let keys = Array.from(results);
			if (keys && keys.length > 0) {
				const key = keys[0][0] as string;
				console.log(`Gemini Selected API Key from normal group: ${key}`);
				return key;
			}

			// If no keys in normal group, try the abnormal group
			results = await this.ctx.storage.sql
				.exec("SELECT api_key FROM api_key_statuses WHERE key_group = 'abnormal' ORDER BY RANDOM() LIMIT 1")
				.raw<any>();
			keys = Array.from(results);
			if (keys && keys.length > 0) {
				const key = keys[0][0] as string;
				console.log(`Gemini Selected API Key from abnormal group: ${key}`);
				return key;
			}

			return null;
		} catch (error) {
			console.error('获取随机API密钥失败:', error);
			return null;
		}
	}

	// ==================== OpenAI Responses API ====================

	/**
	 * Handle OpenAI Responses API requests
	 * POST /v1/responses - Create a response
	 * GET /v1/responses/{id} - Get a response (not implemented, returns error)
	 * DELETE /v1/responses/{id} - Delete a response (not implemented, returns error)
	 */
	private async handleResponsesAPI(request: Request): Promise<Response> {
		console.log('[handleResponsesAPI] Starting to handle Responses API request');
		const authKey = this.env.AUTH_KEY;
		let apiKey: string | null;

		const authHeader = request.headers.get('Authorization');
		apiKey = authHeader?.replace('Bearer ', '') ?? null;
		console.log('[handleResponsesAPI] API key provided:', !!apiKey);

		// 如果启用了客户端 key 透传，直接使用客户端提供的 key
		if (this.env.FORWARD_CLIENT_KEY_ENABLED) {
			if (!apiKey) {
				return new Response('No API key found in the client headers, please check your request!', { status: 400 });
			}
		} else {
			// 传统模式：验证 AUTH_KEY 并使用负载均衡
			if (!apiKey) {
				return new Response('No API key found in the client headers, please check your request!', { status: 400 });
			}

			if (authKey) {
				const token = authHeader?.replace('Bearer ', '');
				if (token !== authKey) {
					return new Response('Unauthorized', { status: 401, headers: fixCors({}).headers });
				}
				apiKey = await this.getRandomApiKey();
				if (!apiKey) {
					return new Response('No API keys configured in the load balancer.', { status: 500 });
				}
			}
		}

		const url = new URL(request.url);
		const pathname = url.pathname;

		const errHandler = (err: Error) => {
			console.error('[handleResponsesAPI] Error:', err);
			const errorResponse = {
				error: {
					message: err.message ?? 'Internal Server Error',
					type: 'server_error',
					code: 'internal_error',
				},
			};
			return new Response(JSON.stringify(errorResponse), {
				...fixCors({ headers: { 'Content-Type': 'application/json' } }),
				status: 500,
			});
		};

		try {
			// POST /v1/responses - Create a response
			if (request.method === 'POST' && pathname.endsWith('/responses')) {
				const reqBody = await request.json();
				return this.handleCreateResponse(reqBody, apiKey).catch(errHandler);
			}

			// GET /v1/responses/{id} - Not implemented (stateless proxy)
			if (request.method === 'GET' && pathname.match(/\/responses\/[^/]+$/)) {
				return new Response(
					JSON.stringify({
						error: {
							message: 'This proxy does not support stateful response retrieval. Use store: false in your requests.',
							type: 'invalid_request_error',
							code: 'not_implemented',
						},
					}),
					{ ...fixCors({ headers: { 'Content-Type': 'application/json' } }), status: 501 }
				);
			}

			// DELETE /v1/responses/{id} - Not implemented
			if (request.method === 'DELETE' && pathname.match(/\/responses\/[^/]+$/)) {
				return new Response(
					JSON.stringify({
						error: {
							message: 'This proxy does not support response deletion.',
							type: 'invalid_request_error',
							code: 'not_implemented',
						},
					}),
					{ ...fixCors({ headers: { 'Content-Type': 'application/json' } }), status: 501 }
				);
			}

			return new Response(
				JSON.stringify({
					error: {
						message: 'Method not allowed',
						type: 'invalid_request_error',
						code: 'method_not_allowed',
					},
				}),
				{ ...fixCors({ headers: { 'Content-Type': 'application/json' } }), status: 405 }
			);
		} catch (err: any) {
			return errHandler(err);
		}
	}

	/**
	 * Create a model response (OpenAI Responses API)
	 * Converts the request to Gemini format and returns OpenAI Responses format
	 */
	private async handleCreateResponse(req: any, apiKey: string): Promise<Response> {
		console.log('[handleCreateResponse] Processing request');

		const DEFAULT_MODEL = 'gemini-2.5-flash';
		let model = DEFAULT_MODEL;

		// Parse model from request
		if (typeof req.model === 'string') {
			if (req.model.startsWith('models/')) {
				model = req.model.substring(7);
			} else if (req.model.startsWith('gemini-') || req.model.startsWith('gemma-') || req.model.startsWith('learnlm-')) {
				model = req.model;
			}
		}

		// Convert Responses API input to Gemini format
		const geminiBody = await this.convertResponsesInputToGemini(req);

		// Determine if streaming
		const isStreaming = req.stream === true;

		const TASK = isStreaming ? 'streamGenerateContent' : 'generateContent';
		let url = `${BASE_URL}/${API_VERSION}/models/${model}:${TASK}`;
		if (isStreaming) {
			url += '?alt=sse';
		}

		console.log('[handleCreateResponse] Calling Gemini API:', url, 'streaming:', isStreaming);

		const response = await fetch(url, {
			method: 'POST',
			headers: makeHeaders(apiKey, { 'Content-Type': 'application/json' }),
			body: JSON.stringify(geminiBody),
		});

		if (!response.ok) {
			const errorText = await response.text();
			console.error('[handleCreateResponse] Gemini API error:', response.status, errorText);
			return new Response(
				JSON.stringify({
					error: {
						message: `Gemini API error: ${errorText}`,
						type: 'api_error',
						code: 'upstream_error',
					},
				}),
				{ ...fixCors({ headers: { 'Content-Type': 'application/json' } }), status: response.status }
			);
		}

		// Generate response IDs
		const responseId = 'resp_' + this.generateId();
		const messageId = 'msg_' + this.generateId();
		const createdAt = Math.floor(Date.now() / 1000);

		if (isStreaming) {
			// Stream response
			return this.handleResponsesStream(response, model, responseId, messageId, createdAt, req);
		} else {
			// Non-streaming response
			return this.handleResponsesNonStream(response, model, responseId, messageId, createdAt, req);
		}
	}

	/**
	 * Convert OpenAI Responses API input to Gemini format
	 */
	private async convertResponsesInputToGemini(req: any): Promise<any> {
		const harmCategory = [
			'HARM_CATEGORY_HATE_SPEECH',
			'HARM_CATEGORY_SEXUALLY_EXPLICIT',
			'HARM_CATEGORY_DANGEROUS_CONTENT',
			'HARM_CATEGORY_HARASSMENT',
			'HARM_CATEGORY_CIVIC_INTEGRITY',
		];

		const safetySettings = harmCategory.map((category) => ({
			category,
			threshold: 'BLOCK_NONE',
		}));

		const contents: any[] = [];

		// Handle instructions (system message)
		if (req.instructions) {
			contents.push({
				role: 'user',
				parts: [{ text: `[System Instructions]\n${req.instructions}` }],
			});
			contents.push({
				role: 'model',
				parts: [{ text: 'Understood. I will follow these instructions.' }],
			});
		}

		// Handle input - can be string or array
		if (typeof req.input === 'string') {
			contents.push({
				role: 'user',
				parts: [{ text: req.input }],
			});
		} else if (Array.isArray(req.input)) {
			for (const item of req.input) {
				if (item.type === 'message') {
					const role = item.role === 'assistant' ? 'model' : 'user';
					const parts: any[] = [];

					if (Array.isArray(item.content)) {
						for (const contentPart of item.content) {
							if (contentPart.type === 'input_text' || contentPart.type === 'output_text') {
								parts.push({ text: contentPart.text });
							} else if (contentPart.type === 'input_image') {
								// Handle image input
								if (contentPart.image_url) {
									parts.push({
										inlineData: {
											mimeType: 'image/jpeg',
											data: contentPart.image_url.replace(/^data:image\/[^;]+;base64,/, ''),
										},
									});
								}
							}
						}
					} else if (typeof item.content === 'string') {
						parts.push({ text: item.content });
					}

					if (parts.length > 0) {
						contents.push({ role, parts });
					}
				} else if (item.role) {
					// Simple message format
					const role = item.role === 'assistant' ? 'model' : 'user';
					const parts: any[] = [];

					if (Array.isArray(item.content)) {
						for (const contentPart of item.content) {
							if (typeof contentPart === 'string') {
								parts.push({ text: contentPart });
							} else if (contentPart.type === 'text' || contentPart.type === 'input_text') {
								parts.push({ text: contentPart.text });
							}
						}
					} else if (typeof item.content === 'string') {
						parts.push({ text: item.content });
					}

					if (parts.length > 0) {
						contents.push({ role, parts });
					}
				}
			}
		}

		// Build generation config
		const generationConfig: any = {};
		if (req.temperature !== undefined) generationConfig.temperature = req.temperature;
		if (req.top_p !== undefined) generationConfig.topP = req.top_p;
		if (req.max_output_tokens !== undefined) generationConfig.maxOutputTokens = req.max_output_tokens;

		// Handle function tools
		const tools: any[] = [];
		if (Array.isArray(req.tools)) {
			const functionDeclarations: any[] = [];
			for (const tool of req.tools) {
				if (tool.type === 'function') {
					functionDeclarations.push({
						name: tool.name,
						description: tool.description,
						parameters: tool.parameters,
					});
				}
			}
			if (functionDeclarations.length > 0) {
				tools.push({ function_declarations: functionDeclarations });
			}
		}

		return {
			contents,
			safetySettings,
			generationConfig,
			...(tools.length > 0 ? { tools } : {}),
		};
	}

	/**
	 * Handle non-streaming response for Responses API
	 */
	private async handleResponsesNonStream(
		response: Response,
		model: string,
		responseId: string,
		messageId: string,
		createdAt: number,
		req: any
	): Promise<Response> {
		let geminiResponse: any;
		try {
			geminiResponse = await response.json();
		} catch (err) {
			console.error('[handleResponsesNonStream] Failed to parse Gemini response:', err);
			return new Response(
				JSON.stringify({
					error: {
						message: 'Failed to parse Gemini response',
						type: 'api_error',
						code: 'parse_error',
					},
				}),
				{ ...fixCors({ headers: { 'Content-Type': 'application/json' } }), status: 500 }
			);
		}

		// Extract text from Gemini response
		let outputText = '';
		const candidate = geminiResponse.candidates?.[0];
		if (candidate?.content?.parts) {
			for (const part of candidate.content.parts) {
				if (part.text) {
					outputText += part.text;
				}
			}
		}

		// Extract usage info
		const usageMetadata = geminiResponse.usageMetadata || {};
		const inputTokens = usageMetadata.promptTokenCount || 0;
		const outputTokens = usageMetadata.candidatesTokenCount || 0;

		// Build OpenAI Responses API response
		const openAIResponse = {
			id: responseId,
			object: 'response',
			created_at: createdAt,
			status: 'completed',
			completed_at: Math.floor(Date.now() / 1000),
			error: null,
			incomplete_details: null,
			instructions: req.instructions || null,
			max_output_tokens: req.max_output_tokens || null,
			model: model,
			output: [
				{
					type: 'message',
					id: messageId,
					status: 'completed',
					role: 'assistant',
					content: [
						{
							type: 'output_text',
							text: outputText,
							annotations: [],
						},
					],
				},
			],
			parallel_tool_calls: req.parallel_tool_calls ?? true,
			previous_response_id: req.previous_response_id || null,
			reasoning: {
				effort: null,
				summary: null,
			},
			store: req.store ?? true,
			temperature: req.temperature ?? 1.0,
			text: {
				format: {
					type: 'text',
				},
			},
			tool_choice: req.tool_choice ?? 'auto',
			tools: req.tools || [],
			top_p: req.top_p ?? 1.0,
			truncation: req.truncation ?? 'disabled',
			usage: {
				input_tokens: inputTokens,
				input_tokens_details: {
					cached_tokens: 0,
				},
				output_tokens: outputTokens,
				output_tokens_details: {
					reasoning_tokens: 0,
				},
				total_tokens: inputTokens + outputTokens,
			},
			user: req.user || null,
			metadata: req.metadata || {},
		};

		return new Response(JSON.stringify(openAIResponse), {
			...fixCors({ headers: { 'Content-Type': 'application/json' } }),
		});
	}

	/**
	 * Handle streaming response for Responses API
	 */
	private handleResponsesStream(
		response: Response,
		model: string,
		responseId: string,
		messageId: string,
		createdAt: number,
		req: any
	): Response {
		const encoder = new TextEncoder();
		let sequenceNumber = 0;

		const that = this;

		const stream = new ReadableStream({
			async start(controller) {
				// Helper to send SSE event
				const sendEvent = (data: any) => {
					controller.enqueue(encoder.encode(`data: ${JSON.stringify(data)}\n\n`));
				};

				// 1. response.created
				sendEvent({
					type: 'response.created',
					response: {
						id: responseId,
						object: 'response',
						created_at: createdAt,
						status: 'in_progress',
						completed_at: null,
						error: null,
						incomplete_details: null,
						instructions: req.instructions || null,
						max_output_tokens: req.max_output_tokens || null,
						model: model,
						output: [],
						parallel_tool_calls: req.parallel_tool_calls ?? true,
						previous_response_id: req.previous_response_id || null,
						reasoning: { effort: null, summary: null },
						store: req.store ?? true,
						temperature: req.temperature ?? 1.0,
						text: { format: { type: 'text' } },
						tool_choice: req.tool_choice ?? 'auto',
						tools: req.tools || [],
						top_p: req.top_p ?? 1.0,
						truncation: req.truncation ?? 'disabled',
						usage: null,
						user: req.user || null,
						metadata: req.metadata || {},
					},
					sequence_number: ++sequenceNumber,
				});

				// 2. response.in_progress
				sendEvent({
					type: 'response.in_progress',
					response: {
						id: responseId,
						object: 'response',
						created_at: createdAt,
						status: 'in_progress',
						completed_at: null,
						error: null,
						incomplete_details: null,
						instructions: req.instructions || null,
						max_output_tokens: req.max_output_tokens || null,
						model: model,
						output: [],
						parallel_tool_calls: req.parallel_tool_calls ?? true,
						previous_response_id: req.previous_response_id || null,
						reasoning: { effort: null, summary: null },
						store: req.store ?? true,
						temperature: req.temperature ?? 1.0,
						text: { format: { type: 'text' } },
						tool_choice: req.tool_choice ?? 'auto',
						tools: req.tools || [],
						top_p: req.top_p ?? 1.0,
						truncation: req.truncation ?? 'disabled',
						usage: null,
						user: req.user || null,
						metadata: req.metadata || {},
					},
					sequence_number: ++sequenceNumber,
				});

				// 3. response.output_item.added
				sendEvent({
					type: 'response.output_item.added',
					output_index: 0,
					item: {
						id: messageId,
						status: 'in_progress',
						type: 'message',
						role: 'assistant',
						content: [],
					},
					sequence_number: ++sequenceNumber,
				});

				// 4. response.content_part.added
				sendEvent({
					type: 'response.content_part.added',
					item_id: messageId,
					output_index: 0,
					content_index: 0,
					part: {
						type: 'output_text',
						text: '',
						annotations: [],
					},
					sequence_number: ++sequenceNumber,
				});

				// Process Gemini SSE stream
				const reader = response.body!.getReader();
				const decoder = new TextDecoder();
				let buffer = '';
				let fullText = '';
				let inputTokens = 0;
				let outputTokens = 0;

				try {
					while (true) {
						const { done, value } = await reader.read();
						if (done) break;

						buffer += decoder.decode(value, { stream: true });
						const lines = buffer.split('\n');
						buffer = lines.pop() || '';

						for (const line of lines) {
							if (line.startsWith('data: ')) {
								const dataStr = line.substring(6).trim();
								if (!dataStr || dataStr === '[DONE]') continue;

								try {
									const data = JSON.parse(dataStr);
									const candidate = data.candidates?.[0];

									if (candidate?.content?.parts) {
										for (const part of candidate.content.parts) {
											if (part.text) {
												fullText += part.text;

												// Send text delta
												sendEvent({
													type: 'response.output_text.delta',
													item_id: messageId,
													output_index: 0,
													content_index: 0,
													delta: part.text,
													sequence_number: ++sequenceNumber,
												});
											}
										}
									}

									// Extract usage from final chunk
									if (data.usageMetadata) {
										inputTokens = data.usageMetadata.promptTokenCount || inputTokens;
										outputTokens = data.usageMetadata.candidatesTokenCount || outputTokens;
									}
								} catch (parseErr) {
									console.error('[handleResponsesStream] Failed to parse SSE data:', parseErr);
								}
							}
						}
					}
				} catch (streamErr) {
					console.error('[handleResponsesStream] Stream error:', streamErr);
				}

				// 5. response.output_text.done
				sendEvent({
					type: 'response.output_text.done',
					item_id: messageId,
					output_index: 0,
					content_index: 0,
					text: fullText,
					sequence_number: ++sequenceNumber,
				});

				// 6. response.content_part.done
				sendEvent({
					type: 'response.content_part.done',
					item_id: messageId,
					output_index: 0,
					content_index: 0,
					part: {
						type: 'output_text',
						text: fullText,
						annotations: [],
					},
					sequence_number: ++sequenceNumber,
				});

				// 7. response.output_item.done
				sendEvent({
					type: 'response.output_item.done',
					output_index: 0,
					item: {
						id: messageId,
						status: 'completed',
						type: 'message',
						role: 'assistant',
						content: [
							{
								type: 'output_text',
								text: fullText,
								annotations: [],
							},
						],
					},
					sequence_number: ++sequenceNumber,
				});

				// 8. response.completed
				const completedAt = Math.floor(Date.now() / 1000);
				sendEvent({
					type: 'response.completed',
					response: {
						id: responseId,
						object: 'response',
						created_at: createdAt,
						status: 'completed',
						completed_at: completedAt,
						error: null,
						incomplete_details: null,
						instructions: req.instructions || null,
						max_output_tokens: req.max_output_tokens || null,
						model: model,
						output: [
							{
								type: 'message',
								id: messageId,
								status: 'completed',
								role: 'assistant',
								content: [
									{
										type: 'output_text',
										text: fullText,
										annotations: [],
									},
								],
							},
						],
						parallel_tool_calls: req.parallel_tool_calls ?? true,
						previous_response_id: req.previous_response_id || null,
						reasoning: { effort: null, summary: null },
						store: req.store ?? true,
						temperature: req.temperature ?? 1.0,
						text: { format: { type: 'text' } },
						tool_choice: req.tool_choice ?? 'auto',
						tools: req.tools || [],
						top_p: req.top_p ?? 1.0,
						truncation: req.truncation ?? 'disabled',
						usage: {
							input_tokens: inputTokens,
							input_tokens_details: { cached_tokens: 0 },
							output_tokens: outputTokens,
							output_tokens_details: { reasoning_tokens: 0 },
							total_tokens: inputTokens + outputTokens,
						},
						user: req.user || null,
						metadata: req.metadata || {},
					},
					sequence_number: ++sequenceNumber,
				});

				controller.close();
			},
		});

		return new Response(stream, {
			headers: {
				...fixCors({}).headers,
				'Content-Type': 'text/event-stream',
				'Cache-Control': 'no-cache',
				Connection: 'keep-alive',
			},
		});
	}

	// ==================== End of OpenAI Responses API ====================

	private async handleOpenAI(request: Request): Promise<Response> {
		console.log('[handleOpenAI] Starting to handle OpenAI request');
		const authKey = this.env.AUTH_KEY;
		let apiKey: string | null;

		const authHeader = request.headers.get('Authorization');
		apiKey = authHeader?.replace('Bearer ', '') ?? null;
		console.log('[handleOpenAI] API key provided:', !!apiKey);

		// 如果启用了客户端 key 透传，直接使用客户端提供的 key
		if (this.env.FORWARD_CLIENT_KEY_ENABLED) {
			if (!apiKey) {
				return new Response('No API key found in the client headers,please check your request!', { status: 400 });
			}
			// 直接使用客户端的 API key，不需要验证
		} else {
			// 传统模式：验证 AUTH_KEY 并使用负载均衡
			if (!apiKey) {
				return new Response('No API key found in the client headers,please check your request!', { status: 400 });
			}

			if (authKey) {
				const token = authHeader?.replace('Bearer ', '');
				if (token !== authKey) {
					return new Response('Unauthorized', { status: 401, headers: fixCors({}).headers });
				}
				apiKey = await this.getRandomApiKey();
				if (!apiKey) {
					return new Response('No API keys configured in the load balancer.', { status: 500 });
				}
			}
		}

		const url = new URL(request.url);
		const pathname = url.pathname;

		const assert = (success: Boolean) => {
			if (!success) {
				throw new HttpError('The specified HTTP method is not allowed for the requested resource', 400);
			}
		};
		const errHandler = (err: Error) => {
			console.error(err);
			return new Response(err.message, fixCors({ statusText: err.message ?? 'Internal Server Error', status: 500 }));
		};

		switch (true) {
			case pathname.endsWith('/chat/completions'):
				assert(request.method === 'POST');
				return this.handleCompletions(await request.json(), apiKey).catch(errHandler);
			case pathname.endsWith('/embeddings'):
				assert(request.method === 'POST');
				return this.handleEmbeddings(await request.json(), apiKey).catch(errHandler);
			case pathname.endsWith('/models'):
				assert(request.method === 'GET');
				return this.handleModels(apiKey).catch(errHandler);
			default:
				throw new HttpError('404 Not Found', 404);
		}
	}
}
