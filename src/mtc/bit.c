unsigned LSB(unsigned n)
{
	return n & 1;
}

unsigned BIT_WIDTH(unsigned n)
{
	unsigned w = 1;
	while (1 << w <= n)
		++w;
	return w;
}

unsigned POPCOUNT(unsigned n)
{
	unsigned count = 0;
	while (n) {
		if (LSB(n))
			++count;
		n >>= 1;
	}
	return count;
}

unsigned BIT_CEIL(unsigned n)
{
	unsigned l = 1;
	while (l < n)
		l <<= 1;
	return l;
}
