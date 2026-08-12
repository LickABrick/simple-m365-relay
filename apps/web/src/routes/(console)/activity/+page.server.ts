import { getActivity } from '$lib/server/operations';
import type { PageServerLoad } from './$types';
export const load: PageServerLoad = () => getActivity();
