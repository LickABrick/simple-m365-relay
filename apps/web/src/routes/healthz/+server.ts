import { text } from '@sveltejs/kit';
export const GET = () => text('ok');
export const HEAD = () => new Response(null, { status: 200 });
