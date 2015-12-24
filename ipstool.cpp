/*
 * Copyright (C) 2015  Christopher J. Howard
 *
 * This file is part of IPS Tool.
 *
 * IPS Tool is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * IPS Tool is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with IPS Tool.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>

static const char IPS_HEADER[] = "PATCH";
static const std::size_t IPS_HEADER_SIZE = 5;
static const char IPS_EOF[] = "EOF";
static const std::size_t IPS_EOF_SIZE = 3;

int main(int argc, const char* argv[])
{
	std::size_t record_count = 0;
	std::size_t byte_count = 0;

	if (argc != 4)
	{
		std::cerr << "usage: ipstool <patch> <input> <output>" << std::endl;
		return EXIT_FAILURE;
	}

	std::ifstream patch(argv[1], std::ios::binary);
	if (!patch.is_open())
	{
		std::cerr << "Failed to open patch file \"" << argv[1] << "\"" << std::endl;
		return EXIT_FAILURE;
	}

	std::ifstream input(argv[2], std::ios::binary);
	if (!input.is_open())
	{
		std::cerr << "Failed to open input file \"" << argv[2] << "\"" << std::endl;
		return EXIT_FAILURE;
	}

	std::ofstream output(argv[3], std::ios::binary);
	if (!output.is_open())
	{
		std::cerr << "Failed to open output file \"" << argv[3] << "\"" << std::endl;
		return EXIT_FAILURE;
	}

	// Check for IPS header
	char header[IPS_HEADER_SIZE];
	patch.read(header, IPS_HEADER_SIZE);
	if (memcmp(IPS_HEADER, header, IPS_HEADER_SIZE) != 0)
	{
		std::cerr << "Patch is not a valid IPS file" << std::endl;
		return EXIT_FAILURE;
	}

	// Copy input file to output file
	output << input.rdbuf();
	input.close();
	output.seekp(0, output.beg);

	// Patch output file
	std::uint32_t offset;
	std::uint16_t size;
	std::uint16_t rle_size;
	std::uint8_t rle_value;
	char buf24[3];
	
	do
	{
		// Read 24-bit offset
		patch.read(buf24, 3);
		offset = (((std::uint8_t)buf24[0]) << 16) | (((std::uint8_t)buf24[1]) << 8) | ((std::uint8_t)buf24[2]);

		// Check for EOF
		if (memcmp(IPS_EOF, buf24, IPS_EOF_SIZE) == 0)
			break;

		// Seek to offset in output file
		output.seekp(offset, output.beg);

		// Read 16-bit size
		patch.read(buf24, 2);
		size = (((std::uint8_t)buf24[0]) << 8) | ((std::uint8_t)buf24[1]);

		if (size != 0)
		{
			// Read uncompressed data
			char* data = new char[size];
			patch.read(data, size);

			// Write data at offset
			output.write(data, size);

			// Free data buffer
			delete[] data;

			// Add size to byte count
			byte_count += size;
		}
		else
		{
			// Read 16-bit RLE size
			patch.read(buf24, 2);
			rle_size = (((std::uint8_t)buf24[0]) << 8) | ((std::uint8_t)buf24[1]);

			// Add RLE size to byte count
			byte_count += rle_size;

			// Read 8-bit RLE value
			patch >> rle_value;

			// Write RLE data
			while (rle_size--)
				output << rle_value;
		}

		// Increment record count
		++record_count;
	}
	while (true);

	patch.close();
	output.close();

	std::cout << "Patched " << byte_count << " bytes with " << record_count << " records" << std::endl;

	return EXIT_SUCCESS;
}
