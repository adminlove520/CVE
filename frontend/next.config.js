/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  swcMinify: true,
  output: 'export',
  basePath: '/CVE',
  images: {
    unoptimized: true,
  },
  assetPrefix: process.env.NEXT_PUBLIC_BASE_PATH || '',
  trailingSlash: true,
  distDir: 'out',
}

module.exports = nextConfig