export const objectToQueryParams = <T extends Record<string, any>>(params: T): string => {
    const searchParams = new URLSearchParams();

    const appendParam = (key: string, value: any) => {
        if (value === undefined || value === null) {
            return;
        }

        if (Array.isArray(value)) {
            value.forEach((item) => {
                appendParam(key, item);
            });
        } else if (typeof value === 'object') {
            searchParams.append(key, JSON.stringify(value));
        } else {
            searchParams.append(key, value.toString());
        }
    };

    Object.entries(params).forEach(([key, value]) => {
        appendParam(key, value);
    });

    return searchParams.toString();
};
