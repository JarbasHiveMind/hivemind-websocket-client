import base64
import enum
import random
import string
import time
from binascii import hexlify, unhexlify
from statistics import mean
from typing import Callable

import click
import pybase64

from z85base91 import Z85B, B91, Z85P
from hivemind_bus_client.exceptions import InvalidEncoding

performance_weight = 0.5
bandwidth_weight = 0.5


class SupportedEncodings(str, enum.Enum):
    """
    Enum representing JSON-based encryption encodings.

    Ciphers output binary data, and JSON needs to transmit that data as plaintext.
    The supported encodings include Base64 and Hex encoding.
    """
    JSON_B91 = "JSON-B91"  # JSON text output with Base91 encoding
    JSON_Z85B = "JSON-Z85B"  # JSON text output with Z85B encoding
    JSON_Z85P = "JSON-Z85P"  # JSON text output with Z85B encoding
    JSON_B64 = "JSON-B64"  # JSON text output with Base64 encoding
    JSON_URLSAFE_B64 = "JSON-URLSAFE-B64"  # JSON text output with url safe Base64 encoding
    JSON_B32 = "JSON-B32"  # JSON text output with Base32 encoding
    JSON_HEX = "JSON-HEX"  # JSON text output with Base16 (Hex) encoding
    JSON_B64_STD = "JSON-B64-stdlib"  # JSON text output with Base64 encoding


def get_encoder(encoding: SupportedEncodings) -> Callable[[bytes], bytes]:
    if encoding == SupportedEncodings.JSON_B64_STD:
        return base64.b64encode
    if encoding == SupportedEncodings.JSON_B64:
        return pybase64.b64encode
    if encoding == SupportedEncodings.JSON_URLSAFE_B64:
        return pybase64.urlsafe_b64encode
    if encoding == SupportedEncodings.JSON_B32:
        return base64.b32encode
    if encoding == SupportedEncodings.JSON_HEX:
        return hexlify
    if encoding == SupportedEncodings.JSON_Z85B:
        return Z85B.encode
    if encoding == SupportedEncodings.JSON_Z85P:
        return Z85P.encode
    if encoding == SupportedEncodings.JSON_B91:
        return B91.encode
    raise InvalidEncoding(f"Invalid encoding: {encoding}")


def get_decoder(encoding: SupportedEncodings) -> Callable[[bytes], bytes]:
    if encoding == SupportedEncodings.JSON_B64_STD:
        return base64.b64decode
    if encoding == SupportedEncodings.JSON_B64:
        return pybase64.b64decode
    if encoding == SupportedEncodings.JSON_URLSAFE_B64:
        return pybase64.urlsafe_b64decode
    if encoding == SupportedEncodings.JSON_B32:
        return base64.b32decode
    if encoding == SupportedEncodings.JSON_HEX:
        return unhexlify
    if encoding == SupportedEncodings.JSON_Z85B:
        return Z85B.decode
    if encoding == SupportedEncodings.JSON_Z85P:
        return Z85P.decode
    if encoding == SupportedEncodings.JSON_B91:
        return B91.decode
    raise InvalidEncoding(f"Invalid encoding: {encoding}")


def generate_random_data(size: int) -> bytes:
    """Generate random binary data of a given size."""
    return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(size)).encode("utf-8")


def benchmark_encoding(encoding: SupportedEncodings, data: bytes) -> dict:
    encoder = get_encoder(encoding)
    decoder = get_decoder(encoding)

    # Measure encoding time
    start_time = time.perf_counter()
    encoded_data = encoder(data)
    encoding_time = time.perf_counter() - start_time

    # Measure decoding time
    start_time = time.perf_counter()
    decoded_data = decoder(encoded_data)
    decoding_time = time.perf_counter() - start_time

    # Calculate size increase
    original_size = len(data)
    encoded_size = len(encoded_data)
    size_increase = encoded_size / original_size

    # Check decoding correctness
    if decoded_data != data:
        raise ValueError(f"Decoded data does not match original data for encoding {encoding}.")

    return {
        "encoding_time": encoding_time,
        "decoding_time": decoding_time,
        "size_increase": size_increase,
        "encoded_size": encoded_size,
        "original_size": original_size,
    }


def calculate_score(encoding_results: list) -> dict:
    """Calculate scores for performance and bandwidth."""
    encoding_times = [r["encoding_time"] for r in encoding_results]
    decoding_times = [r["decoding_time"] for r in encoding_results]
    size_increases = [r["size_increase"] for r in encoding_results]

    avg_encoding_time = mean(encoding_times)
    avg_decoding_time = mean(decoding_times)
    avg_size_increase = mean(size_increases)

    performance_score = 1 / (avg_encoding_time + avg_decoding_time) if avg_encoding_time + avg_decoding_time else 0
    bandwidth_score = 1 - avg_size_increase

    return {"performance_score": performance_score, "bandwidth_score": bandwidth_score}


def normalize_scores(results: dict) -> dict:
    """Normalize performance and bandwidth scores to a 1-100 scale."""
    performance_scores = [r["scores"]["performance_score"] for r in results.values()]
    bandwidth_scores = [r["scores"]["bandwidth_score"] for r in results.values()]

    best_performance = min(performance_scores)
    worst_performance = max(performance_scores)
    best_bandwidth = max(bandwidth_scores)
    worst_bandwidth = min(bandwidth_scores)

    normalized = {}
    for encoding, data in results.items():
        performance = 99 * (best_performance - data["scores"]["performance_score"]) / (
                best_performance - worst_performance
        ) + 1
        bandwidth = 99 * (data["scores"]["bandwidth_score"] - worst_bandwidth) / (
                best_bandwidth - worst_bandwidth
        ) + 1
        normalized[encoding] = {"performance": performance, "bandwidth": bandwidth}
    return normalized


def calculate_aggregate_score(performance: float, bandwidth: float) -> float:
    """Calculate the aggregate score by combining weighted scores."""
    return (performance * performance_weight) + (bandwidth * bandwidth_weight)


def save_detailed_results_to_markdown(results: dict, filename: str):
    """Save detailed benchmark results to a markdown file."""
    with open(filename, "w") as f:
        f.write("# Detailed Benchmark Results\n")
        f.write(
            "| Encoding            | Data Size (bytes) | Encoding Time (sec) | Decoding Time (sec) | Size Increase |\n")
        f.write(
            "|---------------------|-------------------|---------------------|---------------------|---------------|\n")

        for encoding, data in results.items():
            for result in data["results"]:
                encoding_time = result["encoding_time"]
                decoding_time = result["decoding_time"]
                size_increase = result["size_increase"]
                original_size = result["original_size"]
                f.write(
                    f"| {encoding} | {original_size} | {encoding_time:.6f} | {decoding_time:.6f} | {size_increase:.2f} |\n"
                )

    print(f"Detailed results saved to {filename}")


@click.command()
@click.option("--sizes", default="10,100,1000,5000,10000,50000", help="Data sizes to benchmark, comma-separated.")
@click.option("--weights", default="0.5,0.5", help="Weights for performance and bandwidth, comma-separated.")
@click.option("--iterations", default=20, help="Number of iterations to average results.")
def main(sizes: str, weights: str, iterations: int):
    global performance_weight, bandwidth_weight

    sizes = list(map(int, sizes.split(",")))
    performance_weight, bandwidth_weight = map(float, weights.split(","))
    
    # Validate weights
    if not (0 <= performance_weight <= 1 and 0 <= bandwidth_weight <= 1):
        raise ValueError("Weights must be between 0 and 1")
    if abs(performance_weight + bandwidth_weight - 1.0) > 1e-10:
        raise ValueError("Weights must sum to 1")
    encodings_to_test = [
        SupportedEncodings.JSON_B64_STD,
        SupportedEncodings.JSON_B64,
        SupportedEncodings.JSON_URLSAFE_B64,
        SupportedEncodings.JSON_B32,
        SupportedEncodings.JSON_HEX,
        SupportedEncodings.JSON_Z85B,
        SupportedEncodings.JSON_Z85P,
        SupportedEncodings.JSON_B91,
    ]

    results = {}
    for encoding in encodings_to_test:
        encoding_results = []
        for size in sizes:
            print(f"Benchmarking {encoding.value} with {size} bytes of data over {iterations} iterations...")
            aggregated_result = {
                "encoding_time": [],
                "decoding_time": [],
                "size_increase": [],
            }
            for _ in range(iterations):
                data = generate_random_data(size)
                result = benchmark_encoding(encoding, data)
                aggregated_result["encoding_time"].append(result["encoding_time"])
                aggregated_result["decoding_time"].append(result["decoding_time"])
                aggregated_result["size_increase"].append(result["size_increase"])

            # Average results over iterations
            encoding_results.append({
                "encoding_time": mean(aggregated_result["encoding_time"]),
                "decoding_time": mean(aggregated_result["decoding_time"]),
                "size_increase": mean(aggregated_result["size_increase"]),
                "encoded_size": result["encoded_size"],  # Same across iterations
                "original_size": result["original_size"],  # Same across iterations
            })
        scores = calculate_score(encoding_results)
        results[encoding.value] = {"results": encoding_results, "scores": scores}

    normalized_scores = normalize_scores(results)
    table = []

    for encoding, data in normalized_scores.items():
        avg_encoding_time = mean(r["encoding_time"] for r in results[encoding]["results"])
        avg_decoding_time = mean(r["decoding_time"] for r in results[encoding]["results"])
        avg_size_increase = mean(r["size_increase"] for r in results[encoding]["results"])
        performance = data["performance"]
        bandwidth = data["bandwidth"]
        aggregate = calculate_aggregate_score(performance, bandwidth)

        table.append((
            encoding, avg_encoding_time, avg_decoding_time, avg_size_increase,
            performance, bandwidth, aggregate
        ))

    table.sort(key=lambda x: x[6], reverse=True)

    print("\nBenchmark Results:")
    print(
        f"{'Encoding':<20} {'Avg Encoding Time':<20} {'Avg Decoding Time':<20} {'Avg Size Increase':<20} {'Performance':<12} {'Bandwidth':<10} {'Aggregate':<10}")
    print("=" * 110)
    for row in table:
        print(
            f"{row[0]:<20} {row[1]:<20.6f} {row[2]:<20.6f} {row[3]:<20.2f} {row[4]:<12.2f} {row[5]:<10.2f} {row[6]:<10.2f}")

if __name__ == "__main__":
    main()
