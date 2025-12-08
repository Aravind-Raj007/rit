/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  // Export as static HTML for Electron
  output: 'export',
  // Use trailing slash for proper file:// resolution
  trailingSlash: true,
  // Use relative paths for assets (required for file:// protocol)
  assetPrefix: './',
  // Disable image optimization for static export
  images: {
    unoptimized: true,
  },
  // Set base path for production build
  distDir: 'out',
}

module.exports = nextConfig
