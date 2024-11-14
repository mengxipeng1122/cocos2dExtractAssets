const path = require('path');
const nodeExternals = require('webpack-node-externals');
const CopyPlugin = require('copy-webpack-plugin');

const serverConfig = {
  target: 'node',
  externals: [nodeExternals()],
  entry: './src/server.ts',
  module: {
    rules: [
      {
        test: /\.ts$/,
        use: 'ts-loader',
        exclude: /node_modules/,
      },
    ],
  },
  resolve: {
    extensions: ['.ts', '.js'],
  },
  output: {
    filename: 'server.js',
    path: path.resolve(__dirname, 'dist'),
  },
};

const clientConfig = {
  target: 'web',
  entry: {
    index: './src/client/index.ts',
  },
  module: {
    rules: [
      {
        test: /\.ts$/,
        use: 'ts-loader',
        exclude: /node_modules/,
      },
      {
        test: /\.css$/,
        use: ['style-loader', 'css-loader']
      }
    ],
  },
  resolve: {
    extensions: ['.ts', '.js'],
  },
  output: {
    filename: '[name].js',
    path: path.resolve(__dirname, 'dist', 'public', 'scripts'),
  },
  plugins: [
    new CopyPlugin({
      patterns: [
        {
          from: 'src/public',
          to: path.resolve(__dirname, 'dist', 'public'),
        },
      ],
    }),
  ],
};

module.exports = [serverConfig, clientConfig]; 