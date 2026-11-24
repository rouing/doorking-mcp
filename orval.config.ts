export default {
  doorking: {
    input: '../api/docs/openapi.json',
    output: {
      target: './src/generated/api.ts',
      schemas: './src/generated/models',
      client: 'fetch',
      clean: true,
    },
  },
};
